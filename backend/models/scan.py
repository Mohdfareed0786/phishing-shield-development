from pydantic import BaseModel, ConfigDict, Field, field_validator


def to_camel(value: str) -> str:
    first, *rest = value.split('_')
    return first + ''.join(part.capitalize() for part in rest)


class ApiModel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class UrlScanRequest(ApiModel):
    url: str = Field(min_length=1, max_length=2048)

    @field_validator('url')
    @classmethod
    def trim_url(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError('A URL is required.')
        return value


class MessageScanRequest(ApiModel):
    message: str = Field(min_length=1, max_length=10000)

    @field_validator('message')
    @classmethod
    def trim_message(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError('A message is required.')
        return value
