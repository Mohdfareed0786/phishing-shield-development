from __future__ import annotations
from typing import Any
from uuid import UUID
import httpx
from config.settings import settings
from models.user import AuthenticatedUser


class DatabaseUnavailable(Exception):
    pass


def _headers(user: AuthenticatedUser, prefer: str | None = None) -> dict[str, str]:
    if not settings.supabase_url or not settings.supabase_api_key:
        raise DatabaseUnavailable('Supabase is not configured.')
    headers = {
        'apikey': settings.supabase_api_key,
        'Authorization': f'Bearer {user.access_token}',
        'Content-Type': 'application/json',
    }
    if prefer:
        headers['Prefer'] = prefer
    return headers


def _rest_url(table: str) -> str:
    return f"{settings.supabase_url.rstrip('/')}/rest/v1/{table}"


async def _request(method: str, table: str, user: AuthenticatedUser, *, params: dict[str, str] | None = None, payload: dict[str, Any] | None = None, prefer: str | None = None) -> Any:
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
            response = await client.request(method, _rest_url(table), headers=_headers(user, prefer), params=params, json=payload)
        if response.status_code >= 400:
            raise DatabaseUnavailable(f'Supabase data API returned HTTP {response.status_code}.')
        if not response.content:
            return None
        return response.json()
    except DatabaseUnavailable:
        raise
    except (httpx.HTTPError, ValueError) as exc:
        raise DatabaseUnavailable('Supabase data API is unavailable.') from exc


async def save_scan(user: AuthenticatedUser, scan: dict[str, Any]) -> dict[str, Any] | None:
    rows = await _request('POST', 'scan_history', user, payload=scan, prefer='return=representation')
    return rows[0] if isinstance(rows, list) and rows else None


async def list_scans(user: AuthenticatedUser, limit: int = 100) -> list[dict[str, Any]]:
    rows = await _request(
        'GET', 'scan_history', user,
        params={
            'select': 'id,scan_type,input_hash,target_display,risk_score,confidence,classification,detection_reasons,security_checks,threat_sources,analysis,created_at',
            'user_id': f'eq.{user.id}',
            'order': 'created_at.desc',
            'limit': str(min(max(limit, 1), 100)),
        },
    )
    return rows if isinstance(rows, list) else []


async def get_scan(user: AuthenticatedUser, scan_id: UUID) -> dict[str, Any] | None:
    rows = await _request(
        'GET', 'scan_history', user,
        params={
            'select': 'id,scan_type,input_hash,target_display,risk_score,confidence,classification,detection_reasons,security_checks,threat_sources,analysis,created_at',
            'id': f'eq.{scan_id}',
            'user_id': f'eq.{user.id}',
            'limit': '1',
        },
    )
    return rows[0] if isinstance(rows, list) and rows else None


async def get_profile(user: AuthenticatedUser) -> dict[str, Any] | None:
    rows = await _request(
        'GET', 'profiles', user,
        params={'select': 'id,display_name,created_at,updated_at', 'id': f'eq.{user.id}', 'limit': '1'},
    )
    return rows[0] if isinstance(rows, list) and rows else None
