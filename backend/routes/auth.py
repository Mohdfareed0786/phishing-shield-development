import logging
from typing import Annotated
import httpx
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from config.settings import settings
from models.user import AuthenticatedUser

logger = logging.getLogger('phishing_shield.auth')
bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)]) -> AuthenticatedUser:
    if credentials is None or credentials.scheme.lower() != 'bearer':
        raise HTTPException(status_code=401, detail='Authentication required.')
    if not settings.supabase_url or not settings.supabase_api_key:
        raise HTTPException(status_code=503, detail='Authentication service is not configured.')

    try:
        async with httpx.AsyncClient(timeout=6.0, follow_redirects=False) as client:
            response = await client.get(
                f"{settings.supabase_url.rstrip('/')}/auth/v1/user",
                headers={
                    'apikey': settings.supabase_api_key,
                    'Authorization': f'Bearer {credentials.credentials}',
                },
            )
        if response.status_code == 401:
            raise HTTPException(status_code=401, detail='Your session is invalid or expired.')
        if response.status_code >= 400:
            raise HTTPException(status_code=503, detail='Authentication service is temporarily unavailable.')
        payload = response.json()
        return AuthenticatedUser.from_supabase(payload, credentials.credentials)
    except HTTPException:
        raise
    except (httpx.HTTPError, ValueError, KeyError, TypeError):
        logger.warning('Supabase authentication verification failed.')
        raise HTTPException(status_code=503, detail='Authentication service is temporarily unavailable.') from None
