from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException
from database.connection import DatabaseUnavailable, get_profile
from models.user import AuthenticatedUser
from routes.auth import get_current_user

router = APIRouter(prefix='/api', tags=['profile'])
CurrentUser = Annotated[AuthenticatedUser, Depends(get_current_user)]


@router.get('/profile')
async def profile(user: CurrentUser) -> dict:
    try:
        row = await get_profile(user)
    except DatabaseUnavailable:
        raise HTTPException(status_code=503, detail='Profile information is temporarily unavailable.') from None
    return {
        'id': str(user.id),
        'email': user.email,
        'phone': user.phone,
        'displayName': row.get('display_name') if row else None,
        'createdAt': row.get('created_at') if row else None,
    }
