import unittest
import httpx
from main import app
from services.dns_analyzer import DnsResult
from services.message_analyzer import MessageAnalyzer
from services.risk_engine import RiskEngine, RiskFactor
from services.url_analyzer import UrlAnalyzer


class FakeDns:
    async def analyze(self, hostname: str, *, is_ip: bool) -> DnsResult:
        return DnsResult('PASS', 'Test DNS result.', ['203.0.113.10'], [])


class FakeReputation:
    async def lookup(self, original_url: str, normalized_url: str, hostname: str, *, ip_literal: bool) -> dict:
        return {
            'sources': [{'name': 'Test feed', 'status': 'not_configured', 'details': 'Test provider is not configured.'}],
            'riskFactors': [],
            'responses': 0,
            'configured': 0,
        }


class RiskEngineTests(unittest.TestCase):
    def test_score_is_evidence_sum_capped_at_one_hundred(self):
        factors = [
            RiskFactor('one', 'Signal one', 'Observed signal.', 'test evidence', 70),
            RiskFactor('two', 'Signal two', 'Observed signal.', 'test evidence', 55),
        ]
        self.assertEqual(RiskEngine.score(factors), (100, 'CRITICAL RISK'))

    def test_empty_result_is_low_risk_not_a_safety_guarantee(self):
        self.assertEqual(RiskEngine.score([]), (0, 'LOW RISK'))


class AnalyzerTests(unittest.IsolatedAsyncioTestCase):
    async def test_url_report_uses_only_completed_checks_and_does_not_follow_redirects(self):
        analyzer = UrlAnalyzer()
        analyzer.dns = FakeDns()
        analyzer.reputation = FakeReputation()

        report = await analyzer.analyze('https://example.com/verify-account')

        self.assertEqual(report['domain'], 'example.com')
        self.assertGreater(report['riskScore'], 0)
        self.assertEqual(report['confidence'], 45)
        checks = {check['key']: check for check in report['checks']}
        self.assertEqual(checks['redirects']['status'], 'UNKNOWN')
        self.assertIn('never opened', checks['redirects']['details'])
        self.assertNotIn('submittedUrl', report)

    async def test_message_report_does_not_retain_submitted_message(self):
        analyzer = MessageAnalyzer()

        async def skip_links(_url: str) -> dict:
            raise AssertionError('This message contains no link.')

        analyzer._analyze_url = skip_links
        secret_message = 'URGENT: Verify your account immediately. Your account will be suspended. Payment due today. Claim your prize.'
        report = await analyzer.analyze(secret_message)

        self.assertGreaterEqual(report['riskScore'], 60)
        self.assertEqual(report['phishingLikelihood'], report['riskScore'])
        self.assertIn('not a calibrated statistical probability', report['likelihoodMeaning'])
        self.assertNotIn(secret_message, str(report))
        self.assertEqual(report['threatSources'][0]['status'], 'not_applicable')

    async def test_local_destination_is_rejected_before_any_lookup(self):
        analyzer = UrlAnalyzer()
        analyzer.dns = FakeDns()
        analyzer.reputation = FakeReputation()

        with self.assertRaisesRegex(ValueError, 'Local network hostnames'):
            await analyzer.analyze('http://localhost/admin')

    async def test_health_check_and_protected_api(self):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url='http://test') as client:
            health = await client.get('/healthz')
            protected = await client.get('/api/profile')

        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.json()['status'], 'ok')
        self.assertEqual(protected.status_code, 401)
        self.assertEqual(protected.json()['error'], 'Authentication required.')


if __name__ == '__main__':
    unittest.main()
