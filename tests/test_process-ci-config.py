import sys
from pathlib import Path
from textwrap import dedent

import pytest
import yaml
from pydantic import ValidationError

# Import action src
sys.path.append(
    str((Path(__file__).parents[1] / "actions" / "read-ci-config").resolve())
)
from src.process_ci_config import CIConfig, ImageEntry

GENERAL_CI_YAML_WITH_REGISTRIES = """
version: 1
ghcr:
    upload: true
    cve-scan: false
registries:
    docker.io:
        uri: docker.io/ubuntu
        auth:
            - method: basic
              config:
                username: secrets.DOCKER_IO_USERNAME
                password: secrets.DOCKER_IO_PASSWORD
    ecr:
        uri: public.ecr.aws/ubuntu
        auth:
            - method: ecr
              config:
                region: us-east-1
                username: secrets.ECR_USERNAME
                password: secrets.ECR_PASSWORD
    acr:
        uri: myregistry.azurecr.io/ubuntu
        auth:
            - method: bearer
              config:
                token: secrets.ACR_PASSWORD
    ecr-public:
        uri: public.ecr.aws/rocksdev
        auth:
            - method: ecr-public
              config:
                region: us-east-1
                username: secrets.ECR_PUBLIC_USERNAME
                password: secrets.ECR_PUBLIC_PASSWORD
"""

ROCKCRAFT_YAML_MOCK_ROCK_1_0 = """
name: mock-rock
version: 1.0
base: bare
build-base: ubuntu:24.04
"""

ROCKCRAFT_YAML_ANOTHER_ROCK_2_0 = """
name: another-rock
version: 2.0
base: bare
build-base: ubuntu:24.04
"""

ROCKCRAFT_YAML_VERSION_LATEST = """
name: latest-rock
version: latest
base: bare
build-base: ubuntu@24.04
"""

ROCKCRAFT_YAML_INVALID_BASE = """
name: invalid-rock
version: 1.0
base: ubuntu:noble
"""

ROCKCRAFT_YAML_DEVEL_BASE = """
name: devel-rock
version: 1.0
base: bare
build-base: devel
"""

ROCKCRAFT_YAML_2404_BASE = """
name: 2404-base-rock
version: 1.0
base: ubuntu:24.04
"""

# mock the open function to return the content of ROCKCRAFT_YAML_MOCK_ROCK_1_0 or ROCKCRAFT_YAML_ANOTHER_ROCK_2_0
@pytest.fixture
def fake_open(monkeypatch):
    from io import StringIO

    def fake_file_open(file, mode="r", encoding=None):
        if "mock-rock/1.0/rockcraft.yaml" in file:
            return StringIO(ROCKCRAFT_YAML_MOCK_ROCK_1_0)
        elif "another-rock/2.0/rockcraft.yaml" in file:
            return StringIO(ROCKCRAFT_YAML_ANOTHER_ROCK_2_0)
        elif "another-rock/2.0-esm-apps/rockcraft.yaml" in file:
            return StringIO(ROCKCRAFT_YAML_ANOTHER_ROCK_2_0)
        elif "latest-rock/latest/rockcraft.yaml" in file:
            return StringIO(ROCKCRAFT_YAML_VERSION_LATEST)
        elif "invalid-rock/1.0/rockcraft.yaml" in file:
            return StringIO(ROCKCRAFT_YAML_INVALID_BASE)
        elif "devel-rock/1.0/rockcraft.yaml" in file:
            return StringIO(ROCKCRAFT_YAML_DEVEL_BASE)
        elif "24.04-base-rock/1.0/rockcraft.yaml" in file:
            return StringIO(ROCKCRAFT_YAML_2404_BASE)
        else:
            raise FileNotFoundError(f"No such file: {file}")

    monkeypatch.setattr("builtins.open", fake_file_open)


@pytest.fixture
def fake_exists(monkeypatch):
    def fake_os_path_exists(path):
        if "mock-rock/1.0/spread.yaml" in str(path):
            return True
        elif "another-rock/2.0/spread.yaml" in str(path):
            return False
        else:
            return False  # Default to file not existing

    monkeypatch.setattr("pathlib.Path.exists", fake_os_path_exists)


def test_image_name_and_tag_pass(fake_open):
    name, tag = CIConfig.image_name_and_tag("mock-rock/1.0", "")
    assert name == "mock-rock"
    assert tag == "1.0-24.04_edge"
    name, tag = CIConfig.image_name_and_tag("another-rock/2.0", "")
    assert name == "another-rock"
    assert tag == "2.0-24.04_edge"


def test_image_name_and_tag_with_latest_version_pass(fake_open, capsys):
    name, tag = CIConfig.image_name_and_tag("latest-rock/latest", "")
    assert name == "latest-rock"
    assert tag == "latest-24.04_edge"
    captured = capsys.readouterr()
    assert (
        captured.out.rstrip("\n")
        == "::warning file=$file::Using 'latest' as version — tag set to 'latest'"
    )


def test_image_name_and_tag_with_invalid_base_should_fail(fake_open):
    with pytest.raises(
        ValueError,
        match="Base 'ubuntu:noble' in 'invalid-rock/1.0/rockcraft.yaml' does not match the expected pattern.",
    ):
        _ = CIConfig.image_name_and_tag("invalid-rock/1.0", "")


def test_image_with_undefined_registry_should_fail():
    sample_yaml = GENERAL_CI_YAML_WITH_REGISTRIES + dedent(
        """\
        images:
            - directory: mock-rock/1.0
              registries:
                - undefined-registry
        """
    )
    config_data = yaml.safe_load(sample_yaml)
    with pytest.raises(
        ValueError,
        match="Registry 'undefined-registry' in image 'mock-rock/1.0' is not defined in registries.",
    ):
        _ = CIConfig(**config_data)


def test_image_with_invalid_pro_service_should_fail():
    sample_yaml = GENERAL_CI_YAML_WITH_REGISTRIES + dedent(
        """\
        images:
            - directory: mock-rock/1.0
              pro-services:
                - invalid_service
              registries:
                - undefined-registry
        """
    )
    config_data = yaml.safe_load(sample_yaml)
    with pytest.raises(
        ValueError,
        match="Invalid Ubuntu Pro service 'invalid_service'",
    ):
        _ = CIConfig(**config_data)


def test_image_name_and_tag_with_devel_base_pass(fake_open):
    name, tag = CIConfig.image_name_and_tag("devel-rock/1.0", "")
    assert name == "devel-rock"
    assert tag == "1.0-devel_edge"


def test_image_base_with_at_symbol_should_pass(fake_open):
    name, tag = CIConfig.image_name_and_tag("latest-rock/latest", "")
    assert name == "latest-rock"
    assert tag == "latest-24.04_edge"


def test_image_base_override_with_bare_base(fake_open):
    name, tag = CIConfig.image_name_and_tag("mock-rock/1.0", "22.04")
    assert tag == "1.0-22.04_edge"


def test_image_base_not_override_with_not_bare_base(fake_open):
    name, tag = CIConfig.image_name_and_tag("24.04-base-rock/1.0", "22.04")
    assert tag == "1.0-24.04_edge"


def test_image_with_other_wildcard_should_fail():
    sample_yaml = GENERAL_CI_YAML_WITH_REGISTRIES + dedent(
        """\
        images:
            - directory: "*/rockcraft.yaml"
        """
    )
    config_data = yaml.safe_load(sample_yaml)
    with pytest.raises(
        ValueError,
        match="Wildcard '\\*' must be the only character in directory",
    ):
        _ = CIConfig(**config_data)


def test_pydantic_model_loads_configuration():
    sample_yaml = GENERAL_CI_YAML_WITH_REGISTRIES + dedent(
        """\
        images:
            - directory: mock-rock/1.0
              pro-services:
                - esm-apps
              registries:
                - docker.io
        """
    )
    config_data = yaml.safe_load(sample_yaml)
    ci_config = CIConfig(**config_data)
    assert ci_config.ghcr.upload is True  # pylint: disable=no-member
    assert (
        ci_config.ghcr.cve_scan is False  # pylint: disable=no-member
    )  # pylint: disable=no-member
    assert ci_config.model_dump() == {
        "version": 1,
        "ghcr": {"upload": True, "cve_scan": False},
        "registries": {
            "docker.io": {
                "uri": "docker.io/ubuntu",
                "auth": {
                    "registry-auth-method": "basic",
                    "registry-auth-username": "DOCKER_IO_USERNAME",
                    "registry-auth-password": "DOCKER_IO_PASSWORD",
                },
            },
            "ecr": {
                "uri": "public.ecr.aws/ubuntu",
                "auth": {
                    "registry-auth-method": "ecr",
                    "registry-auth-region": "us-east-1",
                    "registry-auth-username": "ECR_USERNAME",
                    "registry-auth-password": "ECR_PASSWORD",
                },
            },
            "acr": {
                "uri": "myregistry.azurecr.io/ubuntu",
                "auth": {
                    "registry-auth-method": "bearer",
                    "registry-auth-token": "ACR_PASSWORD",
                },
            },
            "ecr-public": {
                "uri": "public.ecr.aws/rocksdev",
                "auth": {
                    "registry-auth-method": "ecr-public",
                    "registry-auth-region": "us-east-1",
                    "registry-auth-username": "ECR_PUBLIC_USERNAME",
                    "registry-auth-password": "ECR_PUBLIC_PASSWORD",
                },
            },
        },
        "images": [
            {
                "directory": "mock-rock/1.0",
                "lfs": False,
                "lfs_include": None,
                "pro_services": ["esm-apps"],
                "registries": ["docker.io"],
                "base_override": None,
            }
        ],
    }
    assert ci_config.images == [
        ImageEntry(
            directory="mock-rock/1.0",
            pro_services=["esm-apps"],
            registries=["docker.io"],
        )
    ]


def test_invalid_registry_auth_method_should_fail():
    sample_yaml = dedent(
        """\
        version: 1
        ghcr:
            upload: true
            cve-scan: false
        registries:
            ecr:
                uri: public.ecr.aws/rocksdev
                auth:
                    - method: ecr
                      config:
                        username: ECR_CREDS_USR
                        password: ECR_CREDS_PSW
"""
    )
    config_data = yaml.safe_load(sample_yaml)
    with pytest.raises(ValidationError) as exc_info:
        _ = CIConfig(**config_data)
    assert "registries.ecr.auth.config.region" in str(exc_info.value)


def test_cve_scan_true_with_upload_false_should_fail():
    sample_yaml = dedent(
        """\
        version: 1
        ghcr:
            upload: false
            cve-scan: true
        images:
        """
    )
    config_data = yaml.safe_load(sample_yaml)
    with pytest.raises(ValidationError) as exc_info:
        _ = CIConfig(**config_data)
    assert "cve-scan can not be true if upload is false" in str(exc_info.value)


def test_empty_images_should_pass():
    sample_yaml = GENERAL_CI_YAML_WITH_REGISTRIES + "\nimages:\n"
    config_data = yaml.safe_load(sample_yaml)
    ci_config = CIConfig(**config_data)
    assert ci_config.images == []
    build_matrix = ci_config.build_matrix()
    assert build_matrix == {"include": []}


def test_valid_simple_configuration_should_pass(fake_open, fake_exists):
    sample_yaml = GENERAL_CI_YAML_WITH_REGISTRIES + dedent(
        """
        images:
            - directory: mock-rock/1.0
              pro-services:
                - esm-apps
                - esm-infra
              registries:
                - docker.io
                - ecr
                - ecr-public
        """
    )
    config_data = yaml.safe_load(sample_yaml)
    ci_config = CIConfig(**config_data)
    build_matrix = ci_config.build_matrix()
    expected_build_matrix = {
        "include": [
            {
                "name": "mock-rock",
                "tag": "1.0-24.04_edge",
                "pro-services": "esm-apps,esm-infra",
                "directory": "mock-rock/1.0",
                "lfs": False,
                "lfs-include": '',
                "artifact-name": "mock-rock-1.0-esm-apps-esm-infra",
                "run-tests": True,
            },
        ]
    }
    assert build_matrix == expected_build_matrix
    upload_matrix = ci_config.upload_matrix()
    expected_upload_matrix = {
        "include": [
            {
                "name": "mock-rock",
                "tag": "1.0-24.04_edge",
                "artifact-name": "mock-rock-1.0-esm-apps-esm-infra",
                "pro-enabled": True,
                "registry-uri": "docker.io/ubuntu",
                "registry-auth-method": "basic",
                "registry-auth-username": "DOCKER_IO_USERNAME",
                "registry-auth-password": "DOCKER_IO_PASSWORD",
            },
            {
                "name": "mock-rock",
                "tag": "1.0-24.04_edge",
                "artifact-name": "mock-rock-1.0-esm-apps-esm-infra",
                "pro-enabled": True,
                "registry-uri": "public.ecr.aws/ubuntu",
                "registry-auth-method": "ecr",
                "registry-auth-region": "us-east-1",
                "registry-auth-username": "ECR_USERNAME",
                "registry-auth-password": "ECR_PASSWORD",
            },
            {
                "name": "mock-rock",
                "tag": "1.0-24.04_edge",
                "artifact-name": "mock-rock-1.0-esm-apps-esm-infra",
                "pro-enabled": True,
                "registry-uri": "public.ecr.aws/rocksdev",
                "registry-auth-method": "ecr-public",
                "registry-auth-region": "us-east-1",
                "registry-auth-username": "ECR_PUBLIC_USERNAME",
                "registry-auth-password": "ECR_PUBLIC_PASSWORD",
            },
        ]
    }
    assert sorted(upload_matrix) == sorted(expected_upload_matrix)


def test_conflicting_artifact_names_should_fail(fake_open, fake_exists):
    sample_yaml = GENERAL_CI_YAML_WITH_REGISTRIES + dedent(
        """
        images:
            - directory: another-rock/2.0
              pro-services:
                - esm-apps
            - directory: another-rock/2.0-esm-apps
        """
    )

    config_data = yaml.safe_load(sample_yaml)
    ci_config = CIConfig(**config_data)

    with pytest.raises(ValueError) as exc_info:
        ci_config.build_matrix()
    assert (
        "Artifact generated from 'another-rock/2.0-esm-apps' and 'another-rock/2.0' have conflicting artifact name 'another-rock-2.0-esm-apps'."
        in str(exc_info.value)
    )


def test_image_without_registries_should_pass(fake_open, fake_exists):
    sample_yaml = dedent(
        """\
        version: 1
        ghcr:
            upload: true
            cve-scan: false
        registries:
        images:
            - directory: mock-rock/1.0
        """
    )
    config_data = yaml.safe_load(sample_yaml)
    ci_config = CIConfig(**config_data)
    build_matrix = ci_config.build_matrix()
    expected_build_matrix = {
        "include": [
            {
                "name": "mock-rock",
                "tag": "1.0-24.04_edge",
                "pro-services": "",
                "directory": "mock-rock/1.0",
                "lfs": False,
                "lfs-include": '',
                "artifact-name": "mock-rock-1.0",
                "run-tests": True,
            }
        ]
    }
    assert build_matrix == expected_build_matrix
    upload_matrix = ci_config.upload_matrix()
    assert upload_matrix == {"include": []}


def test_duplicated_image_directory_and_pro_services_should_deduplicate(
    fake_open, fake_exists
):
    sample_yaml = dedent(
        """\
        version: 1
        ghcr:
            upload: true
            cve-scan: false
        registries:
        images:
            - directory: mock-rock/1.0
            - directory: mock-rock/1.0
            - directory: mock-rock/1.0
              pro-services: [ esm-apps ]
            - directory: mock-rock/1.0
              pro-services: [ fips-updates, esm-infra ]
            - directory: mock-rock/1.0
              pro-services: [ fips-updates, esm-infra ]
        """
    )
    config_data = yaml.safe_load(sample_yaml)
    ci_config = CIConfig(**config_data)
    build_matrix = ci_config.build_matrix()
    expected_build_matrix = {
        "include": [
            {
                "name": "mock-rock",
                "tag": "1.0-24.04_edge",
                "pro-services": "",
                "directory": "mock-rock/1.0",
                "lfs": False,
                "lfs-include": '',
                "artifact-name": "mock-rock-1.0",
                "run-tests": True,
            },
            {
                "name": "mock-rock",
                "tag": "1.0-24.04_edge",
                "pro-services": "esm-apps",
                "directory": "mock-rock/1.0",
                "lfs": False,
                "lfs-include": '',
                "artifact-name": "mock-rock-1.0-esm-apps",
                "run-tests": True,
            },
            {
                "name": "mock-rock",
                "tag": "1.0-24.04_edge",
                "pro-services": "esm-infra,fips-updates",
                "directory": "mock-rock/1.0",
                "lfs": False,
                "lfs-include": '',
                "artifact-name": "mock-rock-1.0-esm-infra-fips-updates",
                "run-tests": True,
            },
        ]
    }
    assert build_matrix == expected_build_matrix
    upload_matrix = ci_config.upload_matrix()
    assert upload_matrix == {"include": []}


def test_image_with_duplicated_entries_should_deduplicate(fake_open, fake_exists):
    sample_yaml = GENERAL_CI_YAML_WITH_REGISTRIES + dedent(
        """\
        images:
            - directory: mock-rock/1.0
              registries:
                - docker.io
                - ecr
                - docker.io
            - directory: mock-rock/1.0
              registries:
                - ecr
                - ecr
            - directory: mock-rock/1.0
              pro-services: [esm-apps]
              registries:
                - acr
                - acr
            - directory: mock-rock/1.0
              pro-services: [esm-apps, esm-apps]
              registries:
                - acr
            - directory: mock-rock/1.0
              pro-services: [fips, ros, esm-infra]
              registries:
                - acr
                - ecr
"""
    )
    config_data = yaml.safe_load(sample_yaml)
    ci_config = CIConfig(**config_data)
    build_matrix = ci_config.build_matrix()
    expected_build_matrix = {
        "include": [
            {
                "name": "mock-rock",
                "tag": "1.0-24.04_edge",
                "pro-services": "",
                "directory": "mock-rock/1.0",
                "lfs": False,
                "lfs-include": '',
                "artifact-name": "mock-rock-1.0",
                "run-tests": True,
            },
            {
                "name": "mock-rock",
                "tag": "1.0-24.04_edge",
                "pro-services": "esm-apps",
                "directory": "mock-rock/1.0",
                "lfs": False,
                "lfs-include": '',
                "artifact-name": "mock-rock-1.0-esm-apps",
                "run-tests": True,
            },
            {
                "name": "mock-rock",
                "tag": "1.0-24.04_edge",
                "pro-services": "esm-infra,fips,ros",
                "directory": "mock-rock/1.0",
                "lfs": False,
                "lfs-include": '',
                "artifact-name": "mock-rock-1.0-esm-infra-fips-ros",
                "run-tests": True,
            },
        ]
    }
    assert build_matrix == expected_build_matrix
    upload_matrix = ci_config.upload_matrix()
    expected_upload_matrix = {
        "include": [
            {
                "name": "mock-rock",
                "tag": "1.0-24.04_edge",
                "artifact-name": "mock-rock-1.0",
                "pro-enabled": False,
                "registry-uri": "docker.io/ubuntu",
                "registry-auth-method": "basic",
                "registry-auth-username": "DOCKER_IO_USERNAME",
                "registry-auth-password": "DOCKER_IO_PASSWORD",
            },
            {
                "name": "mock-rock",
                "tag": "1.0-24.04_edge",
                "artifact-name": "mock-rock-1.0",
                "pro-enabled": False,
                "registry-uri": "public.ecr.aws/ubuntu",
                "registry-auth-method": "ecr",
                "registry-auth-region": "us-east-1",
                "registry-auth-username": "ECR_USERNAME",
                "registry-auth-password": "ECR_PASSWORD",
            },
            {
                "name": "mock-rock",
                "tag": "1.0-24.04_edge",
                "artifact-name": "mock-rock-1.0-esm-apps",
                "pro-enabled": True,
                "registry-uri": "myregistry.azurecr.io/ubuntu",
                "registry-auth-method": "bearer",
                "registry-auth-token": "ACR_PASSWORD",
            },
            {
                "name": "mock-rock",
                "tag": "1.0-24.04_edge",
                "artifact-name": "mock-rock-1.0-esm-infra-fips-ros",
                "pro-enabled": True,
                "registry-uri": "myregistry.azurecr.io/ubuntu",
                "registry-auth-method": "bearer",
                "registry-auth-token": "ACR_PASSWORD",
            },
            {
                "name": "mock-rock",
                "tag": "1.0-24.04_edge",
                "artifact-name": "mock-rock-1.0-esm-infra-fips-ros",
                "pro-enabled": True,
                "registry-uri": "public.ecr.aws/ubuntu",
                "registry-auth-method": "ecr",
                "registry-auth-region": "us-east-1",
                "registry-auth-username": "ECR_USERNAME",
                "registry-auth-password": "ECR_PASSWORD",
            },
        ]
    }
    assert sorted(upload_matrix) == sorted(expected_upload_matrix)


@pytest.fixture
def fake_glob(monkeypatch):
    def fake_glob(pattern, recursive=True):
        return ["mock-rock/1.0/rockcraft.yaml", "another-rock/2.0/rockcraft.yaml"]

    monkeypatch.setattr("glob.glob", fake_glob)


def test_images_wildcard_should_glob_rockcraft_yaml(fake_glob, fake_open, fake_exists):
    sample_yaml = dedent(
        """\
        version: 1
        ghcr:
            upload: true
            cve-scan: false
        registries:
        images:
            - directory: "*"
              pro-services:
                - esm-apps
        """
    )
    config_data = yaml.safe_load(sample_yaml)
    ci_config = CIConfig(**config_data)
    assert ci_config.images == [
        ImageEntry(directory="mock-rock/1.0", lfs=False, lfs_include='',
                   pro_services=["esm-apps"]),
        ImageEntry(directory="another-rock/2.0", lfs=False, lfs_include='',
                   pro_services=["esm-apps"]),
    ]
    build_matrix = ci_config.build_matrix()
    expected_matrix = {
        "include": [
            {
                "name": "mock-rock",
                "tag": "1.0-24.04_edge",
                "directory": "mock-rock/1.0",
                "lfs": False,
                "lfs-include": '',
                "artifact-name": "mock-rock-1.0-esm-apps",
                "pro-services": "esm-apps",
                "run-tests": True,
            },
            {
                "name": "another-rock",
                "tag": "2.0-24.04_edge",
                "directory": "another-rock/2.0",
                "lfs": False,
                "lfs-include": '',
                "artifact-name": "another-rock-2.0-esm-apps",
                "pro-services": "esm-apps",
                "run-tests": False,
            },
        ]
    }
    assert build_matrix == expected_matrix
    upload_matrix = ci_config.upload_matrix()
    assert upload_matrix == {"include": []}


def test_multiple_images_wildcard_should_glob_rockcraft_yaml(
    fake_glob, fake_open, fake_exists
):
    sample_yaml = GENERAL_CI_YAML_WITH_REGISTRIES + dedent(
        """
        images:
        - directory: "*"
          registries:
            - docker.io
        - directory: "mock-rock/1.0"
          registries:
            - ecr
        - directory: "another-rock/2.0"
          registries:
            - acr
        - directory: "*"
          registries:
            - ecr
        """
    )
    config_data = yaml.safe_load(sample_yaml)
    ci_config = CIConfig(**config_data)
    build_matrix = ci_config.build_matrix()
    expected_build_matrix = {
        "include": [
            {
                "name": "mock-rock",
                "tag": "1.0-24.04_edge",
                "directory": "mock-rock/1.0",
                "lfs": False,
                "lfs-include": '',
                "artifact-name": "mock-rock-1.0",
                "pro-services": "",
                "run-tests": True,
            },
            {
                "name": "another-rock",
                "tag": "2.0-24.04_edge",
                "directory": "another-rock/2.0",
                "lfs": False,
                "lfs-include": '',
                "artifact-name": "another-rock-2.0",
                "pro-services": "",
                "run-tests": False,
            },
        ]
    }
    assert build_matrix == expected_build_matrix
    upload_matrix = ci_config.upload_matrix()
    expected_upload_matrix = {
        "include": [
            {
                "name": "mock-rock",
                "tag": "1.0-24.04_edge",
                "artifact-name": "mock-rock-1.0",
                "pro-enabled": False,
                "registry-uri": "docker.io/ubuntu",
                "registry-auth-method": "basic",
                "registry-auth-username": "DOCKER_IO_USERNAME",
                "registry-auth-password": "DOCKER_IO_PASSWORD",
            },
            {
                "name": "mock-rock",
                "tag": "1.0-24.04_edge",
                "artifact-name": "mock-rock-1.0",
                "pro-enabled": False,
                "registry-uri": "public.ecr.aws/ubuntu",
                "registry-auth-method": "ecr",
                "registry-auth-region": "us-east-1",
                "registry-auth-username": "ECR_USERNAME",
                "registry-auth-password": "ECR_PASSWORD",
            },
            {
                "name": "another-rock",
                "tag": "2.0-24.04_edge",
                "pro-enabled": False,
                "artifact-name": "another-rock-2.0",
                "registry-uri": "myregistry.azurecr.io/ubuntu",
                "registry-auth-method": "bearer",
                "registry-auth-token": "ACR_PASSWORD",
            },
            {
                "name": "another-rock",
                "tag": "2.0-24.04_edge",
                "pro-enabled": False,
                "artifact-name": "another-rock-2.0",
                "registry-uri": "docker.io/ubuntu",
                "registry-auth-method": "basic",
                "registry-auth-username": "DOCKER_IO_USERNAME",
                "registry-auth-password": "DOCKER_IO_PASSWORD",
            },
            {
                "name": "another-rock",
                "tag": "2.0-24.04_edge",
                "pro-enabled": False,
                "artifact-name": "another-rock-2.0",
                "registry-uri": "public.ecr.aws/ubuntu",
                "registry-auth-method": "ecr",
                "registry-auth-region": "us-east-1",
                "registry-auth-username": "ECR_USERNAME",
                "registry-auth-password": "ECR_PASSWORD",
            },
        ]
    }
    assert upload_matrix == expected_upload_matrix


def test_yaml_missing_images_should_fail():
    sample_yaml = GENERAL_CI_YAML_WITH_REGISTRIES
    config_data = yaml.safe_load(sample_yaml)
    with pytest.raises(ValidationError):
        _ = CIConfig(**config_data)


def test_yaml_missing_registries_should_fail():
    sample_yaml = dedent(
        """\
        version: 1
        ghcr:
            upload: true
            cve-scan: false
        images:
            - directory: mock-rock/1.0
              registries:
                - docker.io
"""
    )
    config_data = yaml.safe_load(sample_yaml)
    with pytest.raises(ValidationError):
        _ = CIConfig(**config_data)


def test_yaml_missing_ghcr_should_fail():
    sample_yaml = dedent(
        """\
        images:
            - directory: mock-rock/1.0
        """
    )
    config_data = yaml.safe_load(sample_yaml)
    with pytest.raises(ValidationError):
        _ = CIConfig(**config_data)


def test_registy_secrets_without_prefix_should_fail():
    sample_yaml = dedent(
        """
        version: 1
        ghcr:
            upload: true
            cve-scan: false
        registries:
            docker.io:
                uri: docker.io/ubuntu
                auth:
                  - method: basic
                    config:
                    username: DOCKER_IO_USERNAME
                    password: DOCKER_IO_PASSWORD
        images:
            - directory: '*'
    """
    )
    config_data = yaml.safe_load(sample_yaml)
    with pytest.raises(ValidationError) as exc_info:
        _ = CIConfig(**config_data)
        assert "Credential name must start with 'secrets.'" in str(exc_info.value)


def test_lfs_missing_should_default_to_false():
    sample_yaml = GENERAL_CI_YAML_WITH_REGISTRIES + dedent(
        """
        images:
            - directory: 'mock-rock/1.0'
    """
    )
    config_data = yaml.safe_load(sample_yaml)
    ci_config = CIConfig(**config_data)
    assert ci_config.images[0].lfs is False  # pylint: disable=no-member


def test_lfs_should_be_selectively_enabled():
    sample_yaml = GENERAL_CI_YAML_WITH_REGISTRIES + dedent(
        """
        images:
            - directory: 'mock-rock/1.0'
              lfs: true
            - directory: 'mock-rock/2.0'
              lfs: false
            - directory: 'mock-rock/3.0'
              lfs: true
    """
    )
    config_data = yaml.safe_load(sample_yaml)
    ci_config = CIConfig(**config_data)
    assert [image.lfs for image in ci_config.images] == [True, False, True]


def test_should_be_able_to_set_lfs_include_exclude():
    sample_yaml = GENERAL_CI_YAML_WITH_REGISTRIES + dedent(
        """
        images:
            - directory: 'mock-rock/1.0'
              lfs: true
              lfs-include: "*.tar.gz"
    """
    )
    config_data = yaml.safe_load(sample_yaml)
    ci_config = CIConfig(**config_data)
    image = ci_config.images[0]
    assert image.lfs is True  # pylint: disable=no-member
    assert image.lfs_include == "*.tar.gz"


def test_override_base_with_bare_base_should_override_tag(fake_open):
    sample_yaml = GENERAL_CI_YAML_WITH_REGISTRIES + dedent(
        """
        images:
            - directory: 'mock-rock/1.0'
              base-override: 'ubuntu:22.04'
    """
    )
    config_data = yaml.safe_load(sample_yaml)
    ci_config = CIConfig(**config_data)
    image = ci_config.images[0]
    assert image.base_override == "ubuntu:22.04"  # pylint: disable=no-member

    build_matrix = ci_config.build_matrix()
    assert build_matrix["include"][0]["tag"] == "1.0-22.04_edge"


def test_override_base_with_non_bare_base_should_not_override_tag(fake_open):
    sample_yaml = GENERAL_CI_YAML_WITH_REGISTRIES + dedent(
        """
        images:
            - directory: '24.04-base-rock/1.0'
              base-override: 'ubuntu:22.04'
    """
    )
    config_data = yaml.safe_load(sample_yaml)
    ci_config = CIConfig(**config_data)
    image = ci_config.images[0]
    assert image.base_override == "ubuntu:22.04"  # pylint: disable=no-member

    build_matrix = ci_config.build_matrix()
    assert build_matrix["include"][0]["tag"] == "1.0-24.04_edge"
