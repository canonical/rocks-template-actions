from enum import Enum
from typing import Type

import pydantic
from pydantic import BaseModel, Field


class BaseAuthConfig(BaseModel):
    @pydantic.model_serializer
    def add_prefix(self):
        return {f"registry-auth-{k}": v for k, v in dict(self).items()}


class BasicAuth(BaseAuthConfig):
    username: str = Field(
        ...,
        description="The name of the GitHub Action secret of the username for basic authentication",
    )
    password: str = Field(
        ...,
        description="The name of the GitHub Action secret of the password for basic authentication",
    )

    @pydantic.field_validator("username", "password")
    def _ensure_secret_format(cls, v):  # pylint: disable=no-self-argument
        if not v or not isinstance(v, str):
            raise ValueError("Credential name must be a non-empty string.")
        if not v.startswith("secrets."):
            raise ValueError("Credential name must start with 'secrets.'")
        return v.removeprefix("secrets.")


class ECRAuth(BasicAuth):
    region: str = Field(..., description="The AWS region for ECR authentication")

    @pydantic.model_serializer
    def add_prefix(self):
        r = super().add_prefix()
        r["registry-auth-method"] = "ecr"
        return r


class ECRPublicAuth(ECRAuth):
    @pydantic.model_serializer
    def add_prefix(self):
        r = super().add_prefix()
        r["registry-auth-method"] = "ecr-public"
        return r


class BearerAuth(BaseAuthConfig):
    token: str = Field(
        ...,
        description="The name of the GitHub Action secret of the token for bearer authentication",
    )

    @pydantic.field_validator("token")
    def _ensure_secret_format(cls, v):  # pylint: disable=no-self-argument
        if not v or not isinstance(v, str):
            raise ValueError("Credential name must be a non-empty string.")
        if not v.startswith("secrets."):
            raise ValueError("Credential name must start with 'secrets.'")
        return v.removeprefix("secrets.")


class AuthType(str, Enum):
    BASIC = "basic"
    BEARER = "bearer"
    ECR = "ecr"
    ECR_PUBLIC = "ecr-public"


AUTH_MODELS: dict[AuthType, Type[BaseModel]] = {
    AuthType.BASIC: BasicAuth,
    AuthType.BEARER: BearerAuth,
    AuthType.ECR: ECRAuth,
    AuthType.ECR_PUBLIC: ECRPublicAuth,
}
