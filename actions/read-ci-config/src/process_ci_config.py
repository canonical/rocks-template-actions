import argparse
import glob
import json
import os
import re
from collections import defaultdict
from typing import Optional, Union

import pydantic
import yaml
from pydantic import BaseModel, Field

from .auth import AUTH_MODELS, AuthType

UBUNTU_PRO_SERVICES = [
    "esm-apps",
    "esm-infra",
    "fips-updates",
    "fips",
    "fips-preview",
    "ros",
    "ros-updates",
]


class GHCRConfig(BaseModel):
    upload: bool = Field(..., description="Flag to indicate if upload is enabled")
    cve_scan: bool = Field(
        ...,
        description="Flag to enable continuous security scanning",
        alias="cve-scan",
    )

    model_config = pydantic.ConfigDict(extra="forbid")

    @pydantic.field_validator("cve_scan")
    def _ensure_cve_scan(cls, v, info):  # pylint: disable=no-self-argument
        if v and not info.data.get("upload", False):
            raise ValueError("cve-scan can not be true if upload is false")
        return v


class RegistrySecretEntry(BaseModel):
    # Field `auth` is an enumerate of different authentication methods
    method: str = Field(
        ..., description="The type of authentication method", alias="method"
    )
    config: Union[tuple(AUTH_MODELS.values())] = Field(
        ..., description="The authentication method for the registry"
    )

    model_config = pydantic.ConfigDict(extra="forbid")

    @pydantic.model_serializer
    def add_prefix(self):
        r = {"registry-auth-method": self.method}
        r.update(self.config.model_dump())  # pylint: disable=no-member
        return r

    @pydantic.field_validator("method", mode="before")
    def _ensure_method_known(cls, v):  # pylint: disable=no-self-argument
        if isinstance(v, str):
            try:
                return AuthType(v)
            except ValueError as e:
                raise ValueError(
                    f"Invalid auth method '{v}'. Supported methods are: {', '.join([m.value for m in AuthType])}."
                ) from e
        return v

    @pydantic.field_validator("config", mode="before")
    def _ensure_config_type(cls, v, info):  # pylint: disable=no-self-argument
        if v is None:
            raise ValueError("Auth config must be provided.")
        if isinstance(v, AUTH_MODELS[AuthType.BASIC]):
            return v
        if not isinstance(v, dict):
            raise ValueError("Auth config must be a dictionary.")
        method = info.data.get("method")
        model_cls = AUTH_MODELS.get(method)
        if model_cls is None:
            raise ValueError(
                f"Unsupported auth method '{method}'. Supported methods are: {', '.join([m.value for m in AuthType])}."
            )
        return model_cls(**v)


class RegistryConfigEntry(BaseModel):
    uri: str = Field(..., description="The URL of the registry")
    auth: RegistrySecretEntry = Field(
        ...,
        description="The GitHub Action secrets for authentication",
    )

    model_config = pydantic.ConfigDict(extra="forbid")

    @pydantic.field_validator("auth", mode="before")
    def _unpack_auth_list(cls, v):  # pylint: disable=no-self-argument
        if not isinstance(v, (list)):
            raise ValueError("Auth must be provided as a list.")
        if len(v) != 1:
            raise ValueError("Auth list must contain exactly one entry.")
        return v[0]


class ImageEntry(BaseModel):
    directory: str = Field(
        ..., description="Path to the directory containing the rockcraft.yaml"
    )

    pro_services: Optional[list[str]] = Field(
        description="List of Ubuntu Pro services to build the rock with",
        default_factory=list,
        alias="pro-services",
    )

    registries: Optional[list[str]] = Field(
        description="List of registry names that match the registry config",
        default_factory=list,
    )

    model_config = pydantic.ConfigDict(extra="forbid", populate_by_name=True)

    @pydantic.field_validator("pro_services", mode="before")
    def _check_pro_services(cls, v):
        invalid_services = [
            service for service in v if service not in UBUNTU_PRO_SERVICES
        ]
        if invalid_services:
            raise ValueError(f"Invalid Ubuntu Pro service '{invalid_services[0]}'")
        return v


class CIConfig(BaseModel):
    version: int = Field(..., description="Version of the CI configuration")
    ghcr: GHCRConfig = Field(
        ..., description="Configuration for GitHub Container Registry"
    )
    # We need to construct registries before images to validate the references of "registries" in images
    registries: dict[str, RegistryConfigEntry] = Field(
        description="Mapping of registry names to their configurations"
    )
    images: list[ImageEntry] = Field(description="List of images to be processed")

    model_config = pydantic.ConfigDict(extra="forbid")

    @pydantic.field_validator("version")
    def _ensure_version_supported(cls, v):  # pylint: disable=no-self-argument
        if v != 1:
            raise ValueError("Only version 1 of the CI configuration is supported.")
        return v

    @pydantic.field_validator("registries", "images", mode="before")
    def _ensure_registries_dict(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return {}
        return v

    @pydantic.field_validator("images", mode="before")
    def _ensure_images_list(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return []
        return v

    @pydantic.field_validator("images", mode="after")
    def _ensure_image_registries_exist(
        cls, v, info
    ):  # pylint: disable=no-self-argument
        if not v:
            return []
        registry_keys = info.data.get("registries", {}).keys()
        for image in v:
            for registry in image.registries:
                if registry not in registry_keys:
                    raise ValueError(
                        f"Registry '{registry}' in image '{image.directory}' is not defined in registries."
                    )
        return v

    @pydantic.field_validator("images", mode="after")
    def _expand_image_directories(cls, v):  # pylint: disable=no-self-argument
        if not v:
            return v
        expanded_images = []
        for image in v:
            if "*" in image.directory:
                if image.directory != "*":
                    raise ValueError(
                        "Wildcard '*' must be the only character in directory"
                    )
                # Expand the wildcard using glob
                dirs = glob.glob("**/rockcraft.yaml", recursive=True)
                for d in dirs:
                    expanded_images.append(
                        ImageEntry(
                            directory=os.path.dirname(d), registries=image.registries
                        )
                    )
            else:
                expanded_images.append(image)
        return expanded_images

    @staticmethod
    def artifact_name(dir: str) -> str:
        return dir.replace("/", "-")

    @staticmethod
    def image_name_and_tag(image_directory: str) -> tuple[str, str]:
        """Read the rockcraft.yaml in the given directory to get the image name and tag.

        Args:
            image_directory (str)

        Raises:
            ValueError

        Returns:
            tuple[str, str]: (name, tag)
        """
        # Pattern to match base version id like '22.04', '20.04', or 'devel'
        base_version_id_pattern = r"(\d{2}(\.|@)\d{2}|devel)$"
        with open(
            os.path.join(image_directory, "rockcraft.yaml"),
            "r",
            encoding="utf-8",
        ) as f:
            rockcraft = yaml.safe_load(f)
            name = rockcraft["name"]
            version = rockcraft["version"]
            channel = "edge"
            base = rockcraft["base"]
            if base == "bare":
                base = rockcraft["build-base"]
            match = re.search(base_version_id_pattern, base)
            if not match:
                raise ValueError(
                    f"Base '{base}' in '{image_directory}/rockcraft.yaml' does not match the expected pattern.\n"
                    + f"See https://documentation.ubuntu.com/rockcraft/stable/reference/rockcraft.yaml/#base for supported base values."
                )
            base = match.group(1)
            if version == "latest":
                print(
                    "::warning file=$file::Using 'latest' as version — tag set to 'latest'"
                )
            tag = f"{version}-{base}_{channel}"
        return name, tag

    def build_matrix(self) -> dict:
        """Generate the build matrix for GitHub Actions.

        Returns:
            dict: Build matrix
        """
        matrix = {"include": []}
        added_artifacts = defaultdict(str)
        added_images = set()

        for image in self.images:  # pylint: disable=not-an-iterable
            key = (image.directory, frozenset(image.pro_services))
            if key in added_images:
                continue
            added_images.add(key)

            pro_services = sorted(image.pro_services)
            name, tag = self.image_name_and_tag(image.directory)
            artifact_base = self.artifact_name(image.directory)
            run_tests = os.path.exists(os.path.join(image.directory, "spread.yaml"))
            artifact_suffix = f"-{'-'.join(pro_services)}" if pro_services else ""

            artifact_name = f"{artifact_base}{artifact_suffix}"
            if artifact_name in added_artifacts:
                raise ValueError(
                    f"Artifact generated from '{image.directory}' and '{added_artifacts[artifact_name]}' have conflicting artifact name '{artifact_name}'."
                )
            added_artifacts[artifact_name] = image.directory

            matrix["include"].append(
                {
                    "name": name,
                    "tag": tag,
                    "directory": image.directory,
                    "pro-services": ",".join(pro_services),
                    "artifact-name": artifact_name,
                    "run-tests": run_tests,
                }
            )
        return matrix

    def upload_matrix(self) -> dict:
        """Generate the upload matrix for GitHub Actions.

        Returns:
            dict: Upload matrix
        """
        matrix = {"include": []}
        image_publish_cfg = defaultdict(set)

        # Group registries by image directory and pro status
        for image in self.images:  # pylint: disable=not-an-iterable
            key = (image.directory, frozenset(image.pro_services))
            image_publish_cfg[key].update(image.registries)

        # Matrix include entries
        for image_tuple, registries in image_publish_cfg.items():
            if not registries:
                continue

            image_dir, image_pro_srvs = image_tuple
            name, tag = self.image_name_and_tag(image_dir)
            base_artifact = self.artifact_name(image_dir)
            artifact_suffix = (
                f"-{'-'.join(sorted(image_pro_srvs))}" if image_pro_srvs else ""
            )

            for registry_name in sorted(registries):
                registry = self.registries[
                    registry_name
                ]  # pylint: disable=unsubscriptable-object

                matrix["include"].append(
                    {
                        "name": name,
                        "tag": tag,
                        "artifact-name": f"{base_artifact}{artifact_suffix}",
                        "pro-enabled": len(image_pro_srvs) > 0,
                        "registry-uri": registry.uri,
                        **registry.auth.model_dump(
                            by_alias=True
                        ),  # pylint: disable=no-member
                    }
                )

        return matrix

    def ghcr_config_json(self, **kwargs):
        return json.dumps(
            self.ghcr.model_dump(by_alias=True), **kwargs  # pylint: disable=no-member
        )


def main():
    parser = argparse.ArgumentParser(
        description="Process and validate CI configuration."
    )
    parser.add_argument(
        "config_path", type=str, help="Path to the CI configuration YAML"
    )
    parser.add_argument(
        "--repo-root", type=str, default="", help="Path to the repository root"
    )
    args = parser.parse_args()

    with open(args.config_path, "r", encoding="utf-8") as f:
        config_data = yaml.safe_load(f)

    os.chdir(args.repo_root)

    ci_config = CIConfig(**config_data)

    # Writes to GitHub outputs
    with open(
        os.environ.get("GITHUB_OUTPUT", "/dev/stdout"), "a", encoding="utf-8"
    ) as gh_out:
        print("Exporting config to", gh_out.name)
        indent = 2 if gh_out.name == "/dev/stdout" else None
        gh_out.write(
            f"ghcr-upload={json.dumps(ci_config.ghcr.upload, indent=indent)}\n"  # pylint: disable=no-member
        )
        gh_out.write(
            f"ghcr-cve-scan={json.dumps(ci_config.ghcr.upload, indent=indent)}\n"  # pylint: disable=no-member
        )
        gh_out.write(
            f"build-matrix={json.dumps(ci_config.build_matrix(), indent=indent)}\n"
        )
        gh_out.write(
            f"upload-matrix={json.dumps(ci_config.upload_matrix(), indent=indent)}\n"
        )


if __name__ == "__main__":
    main()
