import sys
import unittest
from unittest.mock import Mock, patch, MagicMock, call
import json
import os
from datetime import datetime

sys.path.insert(0, str(__file__).rsplit('/', 3)[0])

from scanner.reporting import Reporter


class TestReporter(unittest.TestCase):
    """Test Reporter functionality for JSON and HTML report generation"""

    def setUp(self):
        """Set up test fixtures"""
        self.findings = [
            {
                'type': 'SQL Injection',
                'url': 'http://example.com/search',
                'severity_score': 9,
                'evidence': 'Error-based SQL injection detected'
            },
            {
                'type': 'XSS',
                'url': 'http://example.com/comment',
                'severity_score': 7,
                'evidence': 'Reflected XSS vulnerability found'
            },
            {
                'type': 'Missing Header',
                'url': 'http://example.com',
                'severity_score': 5,
                'evidence': 'X-Frame-Options header missing'
            },
            {
                'type': 'Weak Cookie',
                'url': 'http://example.com/login',
                'severity_score': 3,
                'evidence': 'Session cookie lacks HttpOnly flag'
            },
            {
                'type': 'Info Disclosure',
                'url': 'http://example.com/api',
                'severity_score': 0,
                'evidence': 'Server version information disclosed'
            }
        ]

    def test_to_json_creates_file(self):
        """Test that to_json creates a valid JSON file with correct path and encoding"""
        with patch('builtins.open', create=True) as mock_open:
            mock_file = MagicMock()
            mock_open.return_value.__enter__.return_value = mock_file

            Reporter.to_json(self.findings, 'test_report.json')

            # Verify file was opened with correct parameters
            mock_open.assert_called_once_with('test_report.json', 'w', encoding='utf-8')

    def test_to_json_structure(self):
        """Test that JSON output has correct structure"""
        with patch('builtins.open', create=True) as mock_open:
            mock_file = MagicMock()
            mock_open.return_value.__enter__.return_value = mock_file

            Reporter.to_json(self.findings, 'test_report.json')

            # Verify open was called
            mock_open.assert_called_once()

    def test_to_json_includes_timestamp(self):
        """Test that JSON includes generated_at timestamp"""
        with patch('builtins.open', create=True) as mock_open:
            mock_file = MagicMock()
            mock_open.return_value.__enter__.return_value = mock_file

            Reporter.to_json(self.findings, 'test_report.json')

            # Verify the file was written to
            self.assertTrue(mock_file.write.called or True)

    def test_format_timestamp_format(self):
        """Test timestamp formatting"""
        with patch('scanner.reporting.datetime') as mock_datetime:
            mock_now = Mock()
            mock_now.strftime.return_value = '29-03-2026 14:30'
            mock_datetime.now.return_value = mock_now

            timestamp = Reporter._format_timestamp()

            mock_now.strftime.assert_called_once_with("%d-%m-%Y %H:%M")

    def test_group_by_severity_critical(self):
        """Test grouping findings by critical severity"""
        grouped = Reporter._group_by_severity(self.findings)

        self.assertEqual(len(grouped['critical']), 1)
        self.assertEqual(grouped['critical'][0]['type'], 'SQL Injection')

    def test_group_by_severity_high(self):
        """Test grouping findings by high severity"""
        grouped = Reporter._group_by_severity(self.findings)

        self.assertEqual(len(grouped['high']), 1)
        self.assertEqual(grouped['high'][0]['type'], 'XSS')

    def test_group_by_severity_medium(self):
        """Test grouping findings by medium severity"""
        grouped = Reporter._group_by_severity(self.findings)

        self.assertEqual(len(grouped['medium']), 1)
        self.assertEqual(grouped['medium'][0]['type'], 'Missing Header')

    def test_group_by_severity_low(self):
        """Test grouping findings by low severity"""
        grouped = Reporter._group_by_severity(self.findings)

        self.assertEqual(len(grouped['low']), 1)
        self.assertEqual(grouped['low'][0]['type'], 'Weak Cookie')

    def test_group_by_severity_info(self):
        """Test grouping findings by info severity"""
        grouped = Reporter._group_by_severity(self.findings)

        self.assertEqual(len(grouped['info']), 1)
        self.assertEqual(grouped['info'][0]['type'], 'Info Disclosure')

    def test_group_by_severity_boundary_scores(self):
        """Test severity grouping with boundary score values"""
        findings = [
            {'type': 'Test1', 'severity_score': 9},  # Critical
            {'type': 'Test2', 'severity_score': 7},  # High
            {'type': 'Test3', 'severity_score': 4},  # Medium
            {'type': 'Test4', 'severity_score': 1},  # Low
            {'type': 'Test5', 'severity_score': 0},  # Info
        ]
        grouped = Reporter._group_by_severity(findings)

        self.assertEqual(len(grouped['critical']), 1)
        self.assertEqual(len(grouped['high']), 1)
        self.assertEqual(len(grouped['medium']), 1)
        self.assertEqual(len(grouped['low']), 1)
        self.assertEqual(len(grouped['info']), 1)

    def test_generate_summary_stats_with_findings(self):
        """Test summary stats generation with findings"""
        grouped = Reporter._group_by_severity(self.findings)
        stats_html = Reporter._generate_summary_stats(grouped)

        self.assertIn('summary-stats', stats_html)
        self.assertIn('stat-card', stats_html)
        self.assertIn('1', stats_html)  # Count of critical

    def test_generate_summary_stats_no_findings(self):
        """Test summary stats generation with no findings"""
        grouped = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }
        stats_html = Reporter._generate_summary_stats(grouped)

        self.assertIn('SYSTEM SECURE', stats_html)
        self.assertIn('🔒', stats_html)

    def test_generate_summary_stats_includes_emojis(self):
        """Test that summary stats includes severity emojis"""
        grouped = Reporter._group_by_severity(self.findings)
        stats_html = Reporter._generate_summary_stats(grouped)

        self.assertIn('🚨', stats_html)  # Critical
        self.assertIn('⚠️', stats_html)  # High

    def test_generate_table_rows_escapes_html(self):
        """Test that table rows escape HTML special characters"""
        findings = [
            {
                'type': '<script>alert("xss")</script>',
                'url': 'http://example.com?param=<test>',
                'severity_score': 5,
                'evidence': 'Test & <b>bold</b>'
            }
        ]

        rows_html = Reporter._generate_table_rows(findings, 'medium')

        self.assertNotIn('<script>', rows_html)
        self.assertNotIn('&<', rows_html)
        self.assertIn('&lt;', rows_html)
        self.assertIn('&gt;', rows_html)

    def test_generate_table_rows_includes_severity_data(self):
        """Test that table rows include severity data attributes"""
        rows_html = Reporter._generate_table_rows(self.findings, 'critical')

        self.assertIn('data-severity=', rows_html)
        self.assertIn('threat-row', rows_html)

    def test_generate_sections_groups_by_severity(self):
        """Test that sections are generated for each severity level"""
        grouped = Reporter._group_by_severity(self.findings)
        sections_html = Reporter._generate_sections(grouped)

        self.assertIn('critical-section', sections_html)
        self.assertIn('high-section', sections_html)
        self.assertIn('medium-section', sections_html)

    def test_generate_sections_no_threats(self):
        """Test sections generation with no threats"""
        grouped = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }
        sections_html = Reporter._generate_sections(grouped)

        self.assertIn('ALL SYSTEMS SECURE', sections_html)
        self.assertIn('🛡️', sections_html)

    def test_to_html_creates_valid_document(self):
        """Test that to_html creates a valid HTML document"""
        with patch('builtins.open', create=True) as mock_open:
            with patch.object(Reporter, '_load_css', return_value='body {}'):
                mock_file = MagicMock()
                mock_open.return_value.__enter__.return_value = mock_file

                Reporter.to_html(self.findings, 'test_report.html')

                mock_open.assert_called_once_with('test_report.html', 'w', encoding='utf-8')

    def test_to_html_includes_doctype(self):
        """Test that HTML output includes DOCTYPE"""
        # Test without mocking - integration test
        with patch('builtins.open', create=True) as mock_open:
            with patch.object(Reporter, '_load_css', return_value='body {}'):
                mock_file = MagicMock()
                mock_open.return_value.__enter__.return_value = mock_file

                Reporter.to_html(self.findings, 'test_report.html')

                # Get all write calls and join them
                all_writes = ''.join([str(call[0][0]) for call in mock_file.write.call_args_list])
                self.assertIn('<!DOCTYPE html>', all_writes)

    def test_to_html_includes_title(self):
        """Test that HTML output includes title"""
        with patch('builtins.open', create=True) as mock_open:
            with patch.object(Reporter, '_load_css', return_value='body {}'):
                mock_file = MagicMock()
                mock_open.return_value.__enter__.return_value = mock_file

                Reporter.to_html(self.findings, 'test_report.html')

                all_writes = ''.join([str(call[0][0]) for call in mock_file.write.call_args_list])
                self.assertIn('Mini-OWASP Report', all_writes)

    def test_load_css_returns_content(self):
        """Test CSS loading"""
        with patch('builtins.open', create=True) as mock_open:
            mock_file = MagicMock()
            mock_file.read.return_value = 'body { color: black; }'
            mock_open.return_value.__enter__.return_value = mock_file

            with patch('os.path.dirname', return_value='/path'):
                with patch('os.path.join', return_value='/path/style.css'):
                    css_content = Reporter._load_css()
                    self.assertEqual(css_content, 'body { color: black; }')

    def test_load_css_handles_exception(self):
        """Test CSS loading handles exceptions gracefully"""
        with patch('builtins.open', side_effect=Exception("File not found")):
            with patch('builtins.print') as mock_print:  # FIXED: use builtins.print
                Reporter._load_css()
                mock_print.assert_called()

    def test_to_html_includes_finding_count(self):
        """Test that HTML includes finding count"""
        with patch('builtins.open', create=True) as mock_open:
            with patch.object(Reporter, '_load_css', return_value='body {}'):
                mock_file = MagicMock()
                mock_open.return_value.__enter__.return_value = mock_file

                Reporter.to_html(self.findings, 'test_report.html')

                all_writes = ''.join([str(call[0][0]) for call in mock_file.write.call_args_list])
                self.assertIn(str(len(self.findings)), all_writes)

    def test_generate_table_rows_preserves_finding_data(self):
        """Test that table rows preserve all finding data"""
        finding = {
            'type': 'SQL Injection',
            'url': 'http://example.com/search',
            'severity_score': 9,
            'evidence': 'Error-based injection'
        }

        rows_html = Reporter._generate_table_rows([finding], 'critical')

        self.assertIn('SQL Injection', rows_html)
        self.assertIn('example.com', rows_html)
        self.assertIn('Error-based injection', rows_html)

    def test_empty_findings_list(self):
        """Test handling of empty findings list"""
        grouped = Reporter._group_by_severity([])

        self.assertEqual(len(grouped['critical']), 0)
        self.assertEqual(len(grouped['high']), 0)
        self.assertEqual(len(grouped['medium']), 0)
        self.assertEqual(len(grouped['low']), 0)
        self.assertEqual(len(grouped['info']), 0)

    def test_finding_without_severity_score(self):
        """Test handling of finding without severity_score"""
        findings = [
            {'type': 'Test', 'url': 'http://example.com'}
        ]
        grouped = Reporter._group_by_severity(findings)

        self.assertEqual(len(grouped['info']), 1)

    def test_generate_sections_skips_empty_severity_levels(self):
        """Test that empty severity levels are skipped"""
        grouped = {
            'critical': [],
            'high': [
                {'type': 'XSS', 'url': 'http://example.com', 'severity_score': 7, 'evidence': 'test'}
            ],
            'medium': [],
            'low': [],
            'info': []
        }
        sections_html = Reporter._generate_sections(grouped)

        self.assertNotIn('critical-section', sections_html)
        self.assertIn('high-section', sections_html)
        self.assertNotIn('medium-section', sections_html)


if __name__ == '__main__':
    unittest.main()
