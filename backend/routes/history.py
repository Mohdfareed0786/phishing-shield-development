from typing import Annotated
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query
from database.connection import DatabaseUnavailable, get_scan, list_scans
from models.user import AuthenticatedUser
from routes.auth import get_current_user

router = APIRouter(prefix='/api', tags=['history'])
CurrentUser = Annotated[AuthenticatedUser, Depends(get_current_user)]


@router.get('/history')
async def scan_history(user: CurrentUser, limit: Annotated[int, Query(ge=1, le=100)] = 50) -> dict:
    try:
        scans = await list_scans(user, limit)
    except DatabaseUnavailable:
        raise HTTPException(status_code=503, detail='Scan history is temporarily unavailable.') from None
    for scan in scans:
        analysis = scan.get('analysis')
        if isinstance(analysis, dict):
            analysis['scanId'] = str(scan['id'])
    return {'scans': scans}


@router.get('/history/{scan_id}')
async def scan_history_item(scan_id: UUID, user: CurrentUser) -> dict:
    try:
        scan = await get_scan(user, scan_id)
    except DatabaseUnavailable:
        raise HTTPException(status_code=503, detail='Scan report is temporarily unavailable.') from None
    if not scan:
        raise HTTPException(status_code=404, detail='Scan report not found.')
    analysis = scan.get('analysis')
    if isinstance(analysis, dict):
        analysis['scanId'] = str(scan['id'])
    return {'scan': scan}
