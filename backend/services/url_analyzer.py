import ipaddress
import re
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlsplit, urlunsplit
from services.dns_analyzer import DnsAnalyzer
from services.reputation_service import ReputationService
from services.risk_engine import RiskEngine, RiskFactor

SUSPICIOUS_TERMS = {
    'account': re.compile(r'\b(account|verify|verification|password|login|signin|sign-in|security-check|confirm|update-payment)\b', re.I),
    'urgent': re.compile(r'\b(urgent|suspended|locked|expire|limited|action-required|act-now)\b', re.I),
    'financial': re.compile(r'\b(refund|invoice|payment|bank|wallet|billing|tax-refund)\b', re.I),
}
SHORTENERS = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'cutt.ly', 'rb.gy'}


class UrlAnalyzer:
    def __init__(self) -> None:
        self.dns = DnsAnalyzer()
        self.reputation = ReputationService()
        self.risk = RiskEngine()

    async def analyze(self, submitted_url: str) -> dict:
        original = submitted_url.strip()
        candidate = original if '://' in original else f'https://{original}'
        if len(candidate) > 2048:
            raise ValueError('The URL must be 2,048 characters or fewer.')
        try:
            parsed = urlsplit(candidate)
            hostname = parsed.hostname
            port = parsed.port
        except ValueError:
            raise ValueError('Enter a valid HTTP or HTTPS URL.') from None
        if parsed.scheme.lower() not in {'http', 'https'} or not hostname:
            raise ValueError('Only valid HTTP and HTTPS URLs can be analyzed.')
        if parsed.username is not None or parsed.password is not None:
            raise ValueError('URLs containing embedded usernames or passwords are not accepted.')

        raw_hostname = hostname.rstrip('.').lower()
        try:
            address = ipaddress.ip_address(raw_hostname)
            ip_literal = True
            normalized_host = str(address)
        except ValueError:
            ip_literal = False
            try:
                normalized_host = raw_hostname.encode('idna').decode('ascii').lower()
            except UnicodeError:
                raise ValueError('The URL host is invalid.') from None
            if not normalized_host or len(normalized_host) > 253 or any(len(label) > 63 for label in normalized_host.split('.')):
                raise ValueError('The URL host is invalid.')
        if normalized_host == 'localhost' or normalized_host.endswith(('.localhost', '.local', '.internal')):
            raise ValueError('Local network hostnames are not accepted.')

        try:
            if ip_literal and not address.is_global:
                dns_result = await self.dns.analyze(normalized_host, is_ip=True)
            elif not ip_literal and '.' not in normalized_host:
                dns_result = await self.dns.analyze(normalized_host, is_ip=False)
            else:
                dns_result = await self.dns.analyze(normalized_host, is_ip=ip_literal)
        except Exception:
            dns_result = None
        if dns_result is None:
            from services.dns_analyzer import DnsResult
            dns_result = DnsResult('UNKNOWN', 'DNS lookup could not be completed.', [], [])

        netloc = f'[{normalized_host}]' if ':' in normalized_host else normalized_host
        if port and not ((parsed.scheme == 'https' and port == 443) or (parsed.scheme == 'http' and port == 80)):
            netloc = f'{netloc}:{port}'
        normalized_url = urlunsplit((parsed.scheme.lower(), netloc, parsed.path or '/', parsed.query, ''))

        local_factors: list[RiskFactor] = []
        if parsed.scheme.lower() != 'https':
            local_factors.append(RiskFactor('no_https', 'Connection does not use HTTPS', 'The submitted address uses HTTP, which does not encrypt the connection.', 'http:// scheme', 12))
        if ip_literal:
            local_factors.append(RiskFactor('ip_literal', 'URL uses an IP address', 'IP-literal destinations are harder to verify than an established hostname.', normalized_host, 24))
        if 'xn--' in normalized_host:
            local_factors.append(RiskFactor('punycode', 'Internationalized host label', 'A punycode label can be used in look-alike domains; verify the spelling carefully.', 'xn-- host label', 15))
        elif any(ord(character) > 127 for character in raw_hostname):
            local_factors.append(RiskFactor('unicode_host', 'Non-ASCII domain name', 'Unicode domains can contain visually similar characters from different writing systems.', 'Non-ASCII host label', 12))

        labels = normalized_host.split('.')
        if not ip_literal and len(labels) > 4:
            local_factors.append(RiskFactor('many_subdomains', 'Unusually nested subdomains', 'The hostname contains several nested labels. Confirm the registrable domain before trusting it.', f'{len(labels)} hostname labels', 8))
        if normalized_host in SHORTENERS:
            local_factors.append(RiskFactor('shortener', 'Link-shortening service', 'The final destination is obscured by a URL-shortening service.', normalized_host, 14))
        if len(normalized_url) > 180:
            local_factors.append(RiskFactor('long_url', 'Unusually long URL', 'A long URL can obscure its actual destination or carry unexpected parameters.', f'{len(normalized_url)} characters', 6))
        encoded_count = normalized_url.lower().count('%')
        if encoded_count >= 5:
            local_factors.append(RiskFactor('encoded_url', 'Heavily encoded URL', 'Multiple percent-encoded characters make the destination harder to review.', f'{encoded_count} percent-encoded values', 6))

        matched_terms = []
        target_text = f'{normalized_host}{parsed.path}'
        for category, pattern in SUSPICIOUS_TERMS.items():
            match = pattern.search(target_text)
            if match:
                matched_terms.append((category, match.group(0).lower()))
        if matched_terms:
            evidence = ', '.join(dict.fromkeys(term for _, term in matched_terms))
            categories = {category for category, _ in matched_terms}
            points = 14 if 'account' in categories else 9
            local_factors.append(RiskFactor('suspicious_path_terms', 'Sensitive account or financial terms', 'The hostname or path includes language commonly used to solicit account or payment actions.', evidence, points))

        redirect_keys = [key.lower() for key, _ in parse_qsl(parsed.query, keep_blank_values=True) if key.lower() in {'redirect', 'redirect_uri', 'return', 'returnto', 'continue', 'next', 'target', 'url'}]
        if redirect_keys:
            local_factors.append(RiskFactor('redirect_parameter', 'Redirect-style URL parameter', 'A URL parameter can send visitors to another destination after the initial host.', ', '.join(sorted(set(redirect_keys))[:3]), 8))
        if dns_result.status == 'DANGER':
            local_factors.append(RiskFactor('non_public_dns', 'DNS resolved to a non-public address', 'The hostname returned a non-public address range. The destination itself was not contacted.', ', '.join(dns_result.private_addresses[:2]) or 'non-public IP range', 35))

        intel = await self.reputation.lookup(original, normalized_url, normalized_host, ip_literal=ip_literal)
        factors = local_factors + intel['riskFactors']
        score, classification = self.risk.score(factors)
        coverage = self.risk.coverage(structural=True, dns_performed=dns_result.status != 'UNKNOWN', provider_responses=intel['responses'], provider_count=intel['configured'])

        source_statuses = [source['status'] for source in intel['sources']]
        provider_verdicts = [status for status in source_statuses if status in {'clean', 'suspicious', 'malicious'}]
        if 'malicious' in provider_verdicts:
            intel_status = 'DANGER'
            reputation_status = 'DANGER'
        elif 'suspicious' in provider_verdicts:
            intel_status = 'WARNING'
            reputation_status = 'WARNING'
        elif provider_verdicts:
            intel_status = 'PASS'
            reputation_status = 'PASS'
        else:
            intel_status = 'UNKNOWN'
            reputation_status = 'UNKNOWN'

        severe_local = any(factor.points >= 20 for factor in local_factors)
        structure_status = 'DANGER' if severe_local else 'WARNING' if local_factors else 'PASS'
        checks = [
            {'key': 'https', 'label': 'HTTPS protocol', 'status': 'PASS' if parsed.scheme.lower() == 'https' else 'WARNING', 'details': 'The URL uses HTTPS. The target website was not contacted, so its live TLS certificate was not verified.' if parsed.scheme.lower() == 'https' else 'The URL uses unencrypted HTTP.'},
            {'key': 'url_structure', 'label': 'URL structure', 'status': structure_status, 'details': f'{len(local_factors)} structural indicator(s) were found by local analysis.' if local_factors else 'No elevated structural indicator was found by local analysis.'},
            {'key': 'dns', 'label': 'DNS resolution', 'status': dns_result.status, 'details': dns_result.details},
            {'key': 'domain_reputation', 'label': 'Domain reputation', 'status': reputation_status, 'details': self._reputation_details(intel['sources'])},
            {'key': 'threat_intelligence', 'label': 'Threat intelligence', 'status': intel_status, 'details': self._intel_details(intel['sources'])},
            {'key': 'suspicious_terms', 'label': 'Sensitive URL terms', 'status': 'WARNING' if matched_terms else 'PASS', 'details': f"Observed terms: {', '.join(dict.fromkeys(term for _, term in matched_terms))}." if matched_terms else 'No configured account, urgency, or financial terms were found in the hostname or path.'},
            {'key': 'redirects', 'label': 'Redirect behavior', 'status': 'UNKNOWN', 'details': 'Redirect chains are not followed because the submitted destination is never opened.'},
        ]

        recommended = 'Do not open this link. Verify the sender through an independently obtained official contact.' if score >= 60 else 'Treat this link cautiously. Navigate to the service using a saved bookmark or official app.' if score >= 30 else 'No elevated signals were found in completed checks. This does not prove the destination is safe.'
        target_display = normalized_host
        return {
            'scanType': 'url',
            'targetDisplay': target_display,
            'domain': normalized_host,
            'riskScore': score,
            'confidence': coverage,
            'confidenceMeaning': 'Coverage of local, DNS, and configured threat checks completed; not a guarantee of accuracy.',
            'classification': classification,
            'recommendedAction': recommended,
            'reasons': [factor.as_dict() for factor in factors],
            'checks': checks,
            'threatSources': intel['sources'],
            'analyzedAt': datetime.now(timezone.utc).isoformat(),
        }

    @staticmethod
    def _reputation_details(sources: list[dict]) -> str:
        available = [source for source in sources if source['status'] not in {'not_configured', 'not_applicable'}]
        if not available:
            return 'No reputation provider was configured. This check is unknown, not clean.'
        return f"{len([source for source in available if source['status'] in {'clean', 'malicious', 'suspicious'}])} provider verdict(s) received; unavailable sources remain unknown."

    @staticmethod
    def _intel_details(sources: list[dict]) -> str:
        verdicts = [source for source in sources if source['status'] in {'clean', 'malicious', 'suspicious'}]
        if not verdicts:
            return 'No configured threat feed returned a verdict. No destination connection was attempted.'
        return f"{len(verdicts)} configured feed(s) returned a result. Review the source-by-source findings below."
