from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True)
class AuthenticatedUser:
    id: UUID
    email: str | None
    phone: str | None
    access_token: str

    @classmethod
    def from_supabase(cls, payload: dict, access_token: str) -> 'AuthenticatedUser':
        return cls(
            id=UUID(str(payload['id'])),
            email=payload.get('email'),
            phone=payload.get('phone'),
            access_token=access_token,
        )
