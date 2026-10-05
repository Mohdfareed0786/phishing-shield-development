import asyncio
import re
from datetime import datetime, timezone
from services.risk_engine import RiskEngine, RiskFactor
from services.url_analyzer import UrlAnalyzer

URL_PATTERN = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.IGNORECASE)
SIGNAL_RULES = [
    ('urgency', 'Urgency or time pressure', r'\b(urgent|immediately|act now|within (?:\d+|one|two|three) hours?|expires? today|final notice|last chance|limited time)\b', 12),
    ('credential_request', 'Account or credential request', r'\b(verify (?:your )?(?:account|identity|password)|confirm (?:your )?(?:login|account)|reset (?:your )?password|sign[ -]?in|log[ -]?in|credentials|one[- ]time (?:pass)?code|security code)\b', 18),
    ('threat_or_suspension', 'Threat of account suspension', r'\b(account (?:will be |has been )?(?:suspended|locked|disabled)|service (?:will be )?terminated|access (?:will be )?restricted|legal action|unusual activity detected)\b', 17),
    ('payment_pressure', 'Payment or financial pressure', r'\b(overdue (?:invoice|payment)|failed payment|refund (?:is )?pending|bank account|credit card|wire transfer|payment (?:required|due)|billing issue|tax refund)\b', 14),
    ('unexpected_reward', 'Unexpected prize or reward', r"\b(you(?:'re| are) (?:a )?(?:winner|selected)|claim your (?:prize|reward|gift)|free gift card|cash reward|congratulations.{0,30}won)\b", 14),
    ('impersonation', 'Authority or brand impersonation language', r'\b(IT (?:help ?desk|support)|technical support|security team|CEO|payroll department|customer support|delivery service|tax office)\b', 9),
    ('secrecy_request', 'Request to keep the action secret', r"\b(don't tell anyone|keep this confidential|do not share|secret between us)\b", 14),
]


class MessageAnalyzer:
    def __init__(self) -> None:
        self.url_analyzer = UrlAnalyzer()
        self.risk = RiskEngine()

    async def analyze(self, message: str) -> dict:
        text = message.strip()
        matched: list[RiskFactor] = []
        for key, title, expression, points in SIGNAL_RULES:
            found = re.findall(expression, text, flags=re.IGNORECASE)
            if found:
                evidence = f'Matched signal category: {key.replace("_", " ")}'
                matched.append(RiskFactor(key, title, 'The message includes language that can be used in a phishing or social-engineering attempt.', evidence, points))

        raw_urls = []
        for match in URL_PATTERN.findall(text):
            candidate = match.rstrip('.,!?;:)]}')
            if candidate.lower().startswith('www.'):
                candidate = f'https://{candidate}'
            if candidate not in raw_urls:
                raw_urls.append(candidate)
            if len(raw_urls) >= 5:
                break
        if raw_urls:
            matched.append(RiskFactor('embedded_link', 'Message contains a link', 'Links in unsolicited messages can lead to credential theft or malware.', f'{len(raw_urls)} link(s) extracted', 8))

        urls = await asyncio.gather(*(self._analyze_url(url) for url in raw_urls))
        for index, item in enumerate(urls, start=1):
            if item['riskScore'] >= 60:
                matched.append(RiskFactor(f'url_risk_{index}', 'Elevated risk in an embedded link', 'A link extracted from the message has one or more elevated risk indicators.', f"{item['domain']} · risk {item['riskScore']}/100", min(35, max(12, round(item['riskScore'] * 0.4)))))
            elif item['riskScore'] >= 30:
                matched.append(RiskFactor(f'url_risk_{index}', 'Caution signal in an embedded link', 'A link extracted from the message has some indicators that warrant extra review.', f"{item['domain']} · risk {item['riskScore']}/100", min(18, round(item['riskScore'] * 0.25))))

        score, classification = self.risk.score(matched)
        coverage = min(95, 48 + (12 if raw_urls else 0) + min(35, sum(item['confidence'] for item in urls) // max(1, len(urls)) // 3))
        checks = [
            {'key': 'language_signals', 'label': 'Social engineering language', 'status': 'DANGER' if score >= 60 else 'WARNING' if matched else 'PASS', 'details': f'{len([factor for factor in matched if not factor.key.startswith(("url_risk_", "embedded_link"))])} local language signal(s) found; message content is not retained.' if matched else 'No configured urgency, credential, payment, or impersonation phrase was found.'},
            {'key': 'message_links', 'label': 'Embedded links', 'status': 'WARNING' if raw_urls else 'PASS', 'details': f'{len(raw_urls)} URL(s) extracted and analyzed.' if raw_urls else 'No supported HTTP(S) or www link was found.'},
            {'key': 'message_storage', 'label': 'Message privacy', 'status': 'PASS', 'details': 'Raw message text is analyzed in memory and is excluded from saved scan history.'},
        ]
        sources = self._aggregate_sources(urls)
        if not urls:
            sources = [{'name': 'URL threat feeds', 'status': 'not_applicable', 'details': 'No URL was present in the message.'}]

        if score >= 60:
            recommended = 'Do not reply, share a code, or open its links. Verify the sender using a trusted official channel.'
        elif score >= 30:
            recommended = 'Treat the message cautiously. Confirm unexpected requests independently before taking action.'
        else:
            recommended = 'No elevated message signals were found by local analysis. Still verify unexpected requests and senders.'

        return {
            'scanType': 'message',
            'targetDisplay': 'Message scan',
            'riskScore': score,
            'confidence': coverage,
            'confidenceMeaning': 'Coverage of the local phrase checks and any extracted-link analysis; not a guarantee of accuracy.',
            'classification': classification,
            'phishingLikelihood': score,
            'likelihoodMeaning': 'Evidence-based heuristic indicator score, not a calibrated statistical probability.',
            'recommendedAction': recommended,
            'reasons': [factor.as_dict() for factor in matched],
            'checks': checks,
            'threatSources': sources,
            'extractedUrls': [
                {
                    'domain': item['domain'],
                    'riskScore': item['riskScore'],
                    'confidence': item['confidence'],
                    'classification': item['classification'],
                    'reasons': item['reasons'],
                    'checks': item['checks'],
                    'threatSources': item['threatSources'],
                }
                for item in urls
            ],
            'analyzedAt': datetime.now(timezone.utc).isoformat(),
        }

    async def _analyze_url(self, url: str) -> dict:
        try:
            return await self.url_analyzer.analyze(url)
        except ValueError:
            from urllib.parse import urlsplit
            host = urlsplit(url).hostname or 'unrecognized link'
            return {
                'domain': host[:253], 'riskScore': 25, 'confidence': 30, 'classification': 'MEDIUM RISK',
                'reasons': [{'key': 'invalid_embedded_url', 'title': 'Embedded link could not be analyzed', 'details': 'The extracted link is not a supported public HTTP(S) destination.', 'evidence': 'Invalid, local, or unsupported URL', 'points': 25}],
                'checks': [{'key': 'url_validation', 'label': 'URL validation', 'status': 'WARNING', 'details': 'The link was not opened; its structure could not be fully analyzed.'}],
                'threatSources': [{'name': 'URL threat feeds', 'status': 'not_applicable', 'details': 'Unsupported destinations are not sent to threat feeds.'}],
            }

    @staticmethod
    def _aggregate_sources(urls: list[dict]) -> list[dict]:
        priority = {'malicious': 4, 'suspicious': 3, 'error': 2, 'unknown': 2, 'not_configured': 1, 'clean': 0, 'not_applicable': 0}
        aggregate: dict[str, dict] = {}
        for url in urls:
            for source in url['threatSources']:
                current = aggregate.get(source['name'])
                if current is None or priority.get(source['status'], 1) > priority.get(current['status'], 1):
                    aggregate[source['name']] = source
        return list(aggregate.values())
