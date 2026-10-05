import hashlib
import logging
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException
from database.connection import DatabaseUnavailable, save_scan
from models.scan import MessageScanRequest, UrlScanRequest
from models.user import AuthenticatedUser
from routes.auth import get_current_user
from services.message_analyzer import MessageAnalyzer
from services.rate_limiter import enforce_scan_limit
from services.url_analyzer import UrlAnalyzer

logger = logging.getLogger('phishing_shield.scan')
router = APIRouter(prefix='/api', tags=['scans'])
url_analyzer = UrlAnalyzer()
message_analyzer = MessageAnalyzer()
CurrentUser = Annotated[AuthenticatedUser, Depends(get_current_user)]


@router.post('/scan-url')
async def scan_url(request: UrlScanRequest, user: CurrentUser) -> dict:
    await enforce_scan_limit(str(user.id))
    try:
        result = await url_analyzer.analyze(request.url)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    return await _persist_result(user, request.url, result, 'url')


@router.post('/scan-message')
async def scan_message(request: MessageScanRequest, user: CurrentUser) -> dict:
    await enforce_scan_limit(str(user.id))
    result = await message_analyzer.analyze(request.message)
    return await _persist_result(user, request.message, result, 'message')


async def _persist_result(user: AuthenticatedUser, submitted: str, result: dict, scan_type: str) -> dict:
    safe_target = result.get('targetDisplay') or ('Message scan' if scan_type == 'message' else 'URL scan')
    stored_analysis = {key: value for key, value in result.items() if key not in {'scanId', 'historySaved', 'historyMessage'}}
    stored_analysis['scanId'] = None
    payload = {
        'user_id': str(user.id),
        'scan_type': scan_type,
        'input_hash': hashlib.sha256(submitted.encode('utf-8', errors='replace')).hexdigest(),
        'target_display': safe_target[:255],
        'risk_score': result['riskScore'],
        'confidence': result['confidence'],
        'classification': result['classification'],
        'detection_reasons': result['reasons'],
        'security_checks': result['checks'],
        'threat_sources': result['threatSources'],
        'analysis': stored_analysis,
    }
    try:
        saved = await save_scan(user, payload)
        if saved and saved.get('id'):
            result['scanId'] = str(saved['id'])
            result['historySaved'] = True
            stored_analysis['scanId'] = str(saved['id'])
        else:
            result['historySaved'] = False
            result['historyMessage'] = 'Analysis completed, but the report could not be saved to history.'
    except DatabaseUnavailable:
        logger.warning('Scan history could not be saved for user %s.', user.id)
        result['historySaved'] = False
        result['historyMessage'] = 'Analysis completed, but the report could not be saved to history.'
    except Exception:
        logger.exception('Unexpected scan history write failure for user %s.', user.id)
        result['historySaved'] = False
        result['historyMessage'] = 'Analysis completed, but the report could not be saved to history.'
    return result
