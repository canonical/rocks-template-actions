from typing import Optional
import pydantic
from pydantic import BaseModel, Field


UBUNTU_PRO_SERVICES = frozenset(
    [
        "esm-apps",
        "esm-infra",
        "fips-updates",
        "fips",
        "fips-preview",
        "ros",
        "ros-updates",
    ]
)


class ProConfig(BaseModel):
    token: Optional[str] = Field(
        description="Ubuntu Pro token to use for building the rock",
        default="UBUNTU_PRO_TOKEN",
    )
    artifact_passphrase: Optional[str] = Field(
        description="Passphrase to use for encrypting the Ubuntu Pro artifact",
        alias="artifact-passphrase",
        default="GITHUB_TOKEN",
    )

    model_config = pydantic.ConfigDict(extra="forbid", populate_by_name=True)

    @pydantic.field_validator("token", "artifact_passphrase")
    def _ensure_secret_format(cls, v):  # pylint: disable=no-self-argument
        if not v or not isinstance(v, str):
            raise ValueError("Credential name must be a non-empty string.")
        if not v.startswith("secrets."):
            raise ValueError("Credential name must start with 'secrets.'")
        return v.removeprefix("secrets.")


class Pro(BaseModel):
    services: list[str] = Field(
        description="List of Ubuntu Pro services to build the rock with",
        default_factory=list,
    )
    config: Optional[ProConfig] = Field(
        description="Configuration for building the rock with Ubuntu Pro",
        default=ProConfig()
    )

    model_config = pydantic.ConfigDict(extra="forbid")

    @pydantic.field_validator("services", mode="before")
    def _check_services(cls, v):
        invalid_services = [
            service for service in v if service not in UBUNTU_PRO_SERVICES
        ]
        if invalid_services:
            raise ValueError(f"Invalid Ubuntu Pro service '{invalid_services[0]}'")
        return v

