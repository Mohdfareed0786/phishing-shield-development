import asyncio
import base64
import ipaddress
import httpx
from config.settings import settings
from services.risk_engine import RiskFactor


class ThreatIntelligenceService:
    async def lookup(self, original_url: str, normalized_url: str, hostname: str, *, ip_literal: bool) -> dict:
        if ip_literal:
            try:
                if not ipaddress.ip_address(hostname).is_global:
                    return {
                        'sources': [
                            {'name': 'VirusTotal', 'status': 'not_applicable', 'details': 'Not queried for a non-public IP address.'},
                            {'name': 'Google Safe Browsing', 'status': 'not_applicable', 'details': 'Not queried for a non-public IP address.'},
                            {'name': 'URLhaus', 'status': 'not_applicable', 'details': 'Not queried for a non-public IP address.'},
                            {'name': 'AbuseIPDB', 'status': 'not_applicable', 'details': 'Not queried for a non-public IP address.'},
                        ],
                        'riskFactors': [],
                        'responses': 0,
                        'configured': 0,
                    }
            except ValueError:
                pass

        tasks = [
            self._virus_total(normalized_url),
            self._google_safe_browsing(normalized_url),
            self._urlhaus(normalized_url),
            self._abuse_ipdb(hostname, ip_literal),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        sources = []
        for name, configured, result in zip(
            ('VirusTotal', 'Google Safe Browsing', 'URLhaus', 'AbuseIPDB'),
            self._configured(ip_literal),
            results,
        ):
            if name == 'AbuseIPDB' and not ip_literal:
                sources.append({'name': name, 'status': 'not_applicable', 'details': 'This source checks IP addresses; the URL uses a hostname.'})
            elif isinstance(result, Exception):
                sources.append({'name': name, 'status': 'error', 'details': 'The provider could not be reached; no verdict was inferred.'})
            elif not configured:
                sources.append({'name': name, 'status': 'not_configured', 'details': 'No provider credential is configured; this source was not queried.'})
            else:
                sources.append(result)

        factors: list[RiskFactor] = []
        for source in sources:
            if source['status'] == 'malicious':
                detections = ', '.join(source.get('detections', [])[:3]) or source['name']
                factors.append(RiskFactor(f"feed_{source['name'].lower().replace(' ', '_')}", f"{source['name']} reported a threat", 'A configured threat intelligence provider returned a malicious match.', detections, 60))
            elif source['status'] == 'suspicious':
                detections = ', '.join(source.get('detections', [])[:3]) or source['name']
                factors.append(RiskFactor(f"feed_{source['name'].lower().replace(' ', '_')}", f"{source['name']} reported suspicious activity", 'A configured provider returned a suspicious signal.', detections, 30))

        configured = sum(self._configured(ip_literal))
        responses = sum(source['status'] in {'clean', 'suspicious', 'malicious'} for source in sources)
        return {'sources': sources, 'riskFactors': factors, 'responses': responses, 'configured': configured}

    def _configured(self, ip_literal: bool) -> list[bool]:
        return [
            bool(settings.virus_total_api_key),
            bool(settings.google_safe_browsing_api_key),
            bool(settings.urlhaus_auth_key),
            bool(settings.abuse_ipdb_api_key) and ip_literal,
        ]

    async def _virus_total(self, url: str) -> dict:
        if not settings.virus_total_api_key:
            return {}
        encoded = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')
        async with httpx.AsyncClient(timeout=settings.provider_timeout_seconds, follow_redirects=False) as client:
            response = await client.get(
                f'https://www.virustotal.com/api/v3/urls/{encoded}',
                headers={'x-apikey': settings.virus_total_api_key},
            )
        if response.status_code == 404:
            return {'name': 'VirusTotal', 'status': 'unknown', 'details': 'No existing report was found; absence of a report is not a clean verdict.'}
        response.raise_for_status()
        stats = response.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        malicious = int(stats.get('malicious', 0) or 0)
        suspicious = int(stats.get('suspicious', 0) or 0)
        detections = [f'{malicious} malicious engine(s)', f'{suspicious} suspicious engine(s)']
        if malicious:
            return {'name': 'VirusTotal', 'status': 'malicious', 'details': 'One or more engines marked the URL as malicious.', 'detections': detections}
        if suspicious:
            return {'name': 'VirusTotal', 'status': 'suspicious', 'details': 'One or more engines marked the URL as suspicious.', 'detections': detections}
        if 'harmless' in stats or 'undetected' in stats:
            return {'name': 'VirusTotal', 'status': 'clean', 'details': 'No malicious or suspicious detections appeared in this report.', 'detections': detections}
        return {'name': 'VirusTotal', 'status': 'unknown', 'details': 'The provider returned no usable classification.'}

    async def _google_safe_browsing(self, url: str) -> dict:
        if not settings.google_safe_browsing_api_key:
            return {}
        endpoint = 'https://safebrowsing.googleapis.com/v4/threatMatches:find'
        payload = {
            'client': {'clientId': 'phishing-shield', 'clientVersion': '1.0'},
            'threatInfo': {
                'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                'platformTypes': ['ANY_PLATFORM'],
                'threatEntryTypes': ['URL'],
                'threatEntries': [{'url': url}],
            },
        }
        async with httpx.AsyncClient(timeout=settings.provider_timeout_seconds, follow_redirects=False) as client:
            response = await client.post(endpoint, params={'key': settings.google_safe_browsing_api_key}, json=payload)
        response.raise_for_status()
        matches = response.json().get('matches', [])
        if matches:
            types = sorted({str(match.get('threatType', 'known threat')).replace('_', ' ').lower() for match in matches})
            return {'name': 'Google Safe Browsing', 'status': 'malicious', 'details': 'Google Safe Browsing returned a threat match.', 'detections': types[:4]}
        return {'name': 'Google Safe Browsing', 'status': 'clean', 'details': 'No matching URL threat entry was returned.'}

    async def _urlhaus(self, url: str) -> dict:
        if not settings.urlhaus_auth_key:
            return {}
        async with httpx.AsyncClient(timeout=settings.provider_timeout_seconds, follow_redirects=False) as client:
            response = await client.post(
                'https://urlhaus-api.abuse.ch/v1/url/',
                headers={'Auth-Key': settings.urlhaus_auth_key, 'User-Agent': 'phishing-shield/1.0'},
                data={'url': url},
            )
        response.raise_for_status()
        payload = response.json()
        status = payload.get('query_status')
        if status == 'is_urlhaus':
            tags = [str(tag) for tag in payload.get('tags', []) if tag]
            return {'name': 'URLhaus', 'status': 'malicious', 'details': 'The URL appears in the URLhaus malware URL database.', 'detections': tags[:4] or ['malware URL']}
        if status == 'no_results':
            return {'name': 'URLhaus', 'status': 'clean', 'details': 'No matching entry was returned by URLhaus.'}
        return {'name': 'URLhaus', 'status': 'unknown', 'details': 'URLhaus returned no usable classification.'}

    async def _abuse_ipdb(self, hostname: str, ip_literal: bool) -> dict:
        if not settings.abuse_ipdb_api_key or not ip_literal:
            return {}
        async with httpx.AsyncClient(timeout=settings.provider_timeout_seconds, follow_redirects=False) as client:
            response = await client.get(
                'https://api.abuseipdb.com/api/v2/check',
                params={'ipAddress': hostname, 'maxAgeInDays': '90'},
                headers={'Key': settings.abuse_ipdb_api_key, 'Accept': 'application/json'},
            )
        response.raise_for_status()
        score = int(response.json().get('data', {}).get('abuseConfidenceScore', 0) or 0)
        if score >= 25:
            return {'name': 'AbuseIPDB', 'status': 'suspicious', 'details': 'AbuseIPDB reported recent abuse for this public IP address.', 'detections': [f'{score}% abuse confidence score']}
        return {'name': 'AbuseIPDB', 'status': 'clean', 'details': 'The reported abuse confidence score is below the configured alert threshold.', 'detections': [f'{score}% abuse confidence score']}
