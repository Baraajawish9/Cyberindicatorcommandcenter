from unittest.mock import patch
from pathlib import Path

from django.test import SimpleTestCase

from .forms import IPReportForm
from .services import SourceResult, build_ip_report


class IPReportFormTests(SimpleTestCase):
    def test_accepts_valid_ipv4(self):
        form = IPReportForm({'ip_address': '8.8.8.8'})

        self.assertTrue(form.is_valid())
        self.assertEqual(form.cleaned_data['ip_address'], '8.8.8.8')

    def test_rejects_invalid_ip(self):
        form = IPReportForm({'ip_address': 'not-an-ip'})

        self.assertFalse(form.is_valid())
        self.assertIn('ip_address', form.errors)

    def test_trims_trailing_slash(self):
        form = IPReportForm({'ip_address': '8.8.8.8/'})

        self.assertTrue(form.is_valid())
        self.assertEqual(form.cleaned_data['ip_address'], '8.8.8.8')

    def test_extracts_ip_from_url(self):
        form = IPReportForm({'ip_address': 'https://8.8.8.8/path?x=1'})

        self.assertTrue(form.is_valid())
        self.assertEqual(form.cleaned_data['ip_address'], '8.8.8.8')

    def test_accepts_domain(self):
        form = IPReportForm({'ip_address': 'Example.COM/'})

        self.assertTrue(form.is_valid())
        self.assertEqual(form.cleaned_data['ip_address'], 'example.com')

    def test_extracts_domain_from_url(self):
        form = IPReportForm({'ip_address': 'https://sub.example.com/path?x=1'})

        self.assertTrue(form.is_valid())
        self.assertEqual(form.cleaned_data['ip_address'], 'sub.example.com')


class ReportBuilderTests(SimpleTestCase):
    @patch('dashboard.services._collect_sources')
    def test_combines_available_source_scores(self, collect_sources):
        collect_sources.return_value = [
            SourceResult('VirusTotal', 'ok', 20, {}, {}),
            SourceResult('AbuseIPDB', 'ok', 80, {}, {}),
            SourceResult('AlienVault OTX', 'missing_key', None, {}, {}, 'missing'),
        ]

        report = build_ip_report('8.8.8.8')

        self.assertEqual(report['overall_score'], 50)
        self.assertEqual(report['risk_level']['label'], 'High')

    @patch('dashboard.services._resolve_domain')
    @patch('dashboard.services._collect_sources')
    def test_builds_domain_report(self, collect_sources, resolve_domain):
        resolve_domain.return_value = '93.184.216.34'
        collect_sources.return_value = [
            SourceResult('VirusTotal', 'ok', 10, {}, {}),
            SourceResult('AbuseIPDB', 'ok', 20, {}, {}),
            SourceResult('AlienVault OTX', 'ok', 30, {}, {}),
        ]

        report = build_ip_report('example.com')

        self.assertEqual(report['display_value'], 'example.com')
        self.assertEqual(report['indicator_kind'], 'domain')
        self.assertEqual(report['resolved_ip'], '93.184.216.34')
        self.assertEqual(report['overall_score'], 20)

    def test_public_template_hides_source_names(self):
        content = Path('dashboard/templates/dashboard/index.html').read_text()

        self.assertNotIn('VirusTotal', content)
        self.assertNotIn('AbuseIPDB', content)
        self.assertNotIn('AlienVault', content)
        self.assertNotIn('OTX', content)
        self.assertIn('Combined intelligence report', content)

    @patch('dashboard.services._collect_sources')
    def test_combined_report_text_hides_source_names(self, collect_sources):
        collect_sources.return_value = [
            SourceResult(
                'VirusTotal',
                'ok',
                20,
                {'Malicious vendors': 1, 'Suspicious vendors': 0, 'Country': 'US', 'ASN owner': 'Example ASN'},
                {'analysis_stats': {'malicious': 1}, 'tags': ['scanner'], 'country_code': 'US'},
            ),
            SourceResult(
                'AbuseIPDB',
                'ok',
                80,
                {'Abuse confidence': '80%', 'Total reports': 2, 'ISP': 'Example ISP'},
                {'recent_reports': [{'reportedAt': '2026-05-03', 'comment': 'test report'}]},
            ),
            SourceResult(
                'AlienVault OTX',
                'ok',
                40,
                {'Pulse count': 3},
                {'pulses': [{'name': 'Example collection', 'modified': '2026-05-03'}]},
            ),
        ]

        report = build_ip_report('8.8.8.8')
        content = ' '.join(report['highlights'])

        self.assertNotIn('VirusTotal', content)
        self.assertNotIn('AbuseIPDB', content)
        self.assertNotIn('AlienVault', content)
        self.assertNotIn('OTX', content)
        self.assertIn('malicious', content)
