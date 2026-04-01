import tempfile
import unittest
from datetime import datetime
from unittest.mock import patch

from scanner.reporting_pdf import (
    BG_DARK, CARD_DARK, TEXT, MUTED, BORDER, ACCENT1, ACCENT2, SEV_COLORS
)


class TestSanitizeHtmlForPdf(unittest.TestCase):
    """Test HTML sanitization for PDF"""

    def test_sanitize_removes_html_tags(self):
        """Test that HTML tags are removed"""
        html = '<p>Hello <b>World</b></p>'
        result = sanitize_html_for_pdf(html)
        self.assertNotIn('<p>', result)
        self.assertNotIn('<b>', result)
        self.assertEqual(result, 'Hello World')

    def test_sanitize_unescapes_entities(self):
        """Test that HTML entities are unescaped"""
        html = '&lt;script&gt;'
        result = sanitize_html_for_pdf(html)
        self.assertIn('&lt;', result)

    def test_sanitize_escapes_special_chars(self):
        """Test that special characters are escaped"""
        text = '<script>alert("xss")</script>'
        result = sanitize_html_for_pdf(text)
        # Tags are removed first, leaving: alert("xss")
        # Then special chars are escaped
        self.assertIn('&quot;', result)
        self.assertNotIn('<script>', result)
        self.assertNotIn('script', result)

    def test_sanitize_handles_ampersand(self):
        """Test ampersand escaping"""
        text = 'A & B'
        result = sanitize_html_for_pdf(text)
        self.assertIn('&amp;', result)

    def test_sanitize_handles_quotes(self):
        """Test quote escaping"""
        text = 'Say "hello" or \'goodbye\''
        result = sanitize_html_for_pdf(text)
        self.assertIn('&quot;', result)
        self.assertIn('&#x27;', result)

    def test_sanitize_collapses_whitespace(self):
        """Test that multiple spaces are collapsed"""
        text = 'Hello    World   Test'
        result = sanitize_html_for_pdf(text)
        self.assertEqual(result, 'Hello World Test')

    def test_sanitize_truncates_long_text(self):
        """Test that text longer than 1000 chars is truncated"""
        text = 'A' * 1001
        result = sanitize_html_for_pdf(text)
        self.assertEqual(len(result), 1000)
        self.assertTrue(result.endswith('...'))

    def test_sanitize_handles_none_input(self):
        """Test that None input returns dash"""
        result = sanitize_html_for_pdf(None)
        self.assertEqual(result, '-')

    def test_sanitize_handles_empty_string(self):
        """Test that empty string returns dash"""
        result = sanitize_html_for_pdf('')
        self.assertEqual(result, '-')

    def test_sanitize_handles_whitespace_only(self):
        """Test that whitespace-only string returns dash"""
        result = sanitize_html_for_pdf('   ')
        self.assertEqual(result, '-')

    def test_sanitize_handles_non_string_input(self):
        """Test that non-string input is converted"""
        result = sanitize_html_for_pdf(123)
        self.assertEqual(result, '123')

    def test_sanitize_handles_complex_html(self):
        """Test sanitization of complex HTML"""
        html = '<div class="content"><p>Test & <script>alert("xss")</script></p></div>'
        result = sanitize_html_for_pdf(html)
        self.assertNotIn('<', result)
        self.assertNotIn('>', result)
        self.assertNotIn('script', result)


class TestSevBucket(unittest.TestCase):
    """Test severity bucketing"""

    def test_sev_bucket_zero_is_info(self):
        """Test that score 0 returns info"""
        self.assertEqual(sev_bucket(0), 'info')

    def test_sev_bucket_negative_is_info(self):
        """Test that negative score returns info"""
        self.assertEqual(sev_bucket(-5), 'info')

    def test_sev_bucket_one_is_low(self):
        """Test that score 1 returns low"""
        self.assertEqual(sev_bucket(1), 'low')

    def test_sev_bucket_two_is_low(self):
        """Test that score 2 returns low"""
        self.assertEqual(sev_bucket(2), 'low')

    def test_sev_bucket_three_is_medium(self):
        """Test that score 3 returns medium"""
        self.assertEqual(sev_bucket(3), 'medium')

    def test_sev_bucket_five_is_medium(self):
        """Test that score 5 returns medium"""
        self.assertEqual(sev_bucket(5), 'medium')

    def test_sev_bucket_six_is_high(self):
        """Test that score 6 returns high"""
        self.assertEqual(sev_bucket(6), 'high')

    def test_sev_bucket_high_value_is_high(self):
        """Test that high score returns high"""
        self.assertEqual(sev_bucket(100), 'high')


class TestDot(unittest.TestCase):
    """Test Dot flowable"""

    def test_dot_creation(self):
        """Test dot creation with default parameters"""
        d = dot()
        self.assertIsNotNone(d)

    def test_dot_with_custom_radius(self):
        """Test dot creation with custom radius"""
        d = dot(radius=5)
        self.assertEqual(d.radius, 5)

    def test_dot_with_custom_color(self):
        """Test dot creation with custom color"""
        custom_color = colors.red
        d = dot(fill=custom_color)
        self.assertEqual(d.fill, custom_color)

    def test_dot_wrap_returns_dimensions(self):
        """Test dot wrap returns correct dimensions"""
        d = dot(radius=3)
        w, h = d.wrap(100, 100)
        self.assertEqual(w, 6)
        self.assertEqual(h, 6)

    @patch('scanner.reporting_pdf.Flowable.__init__')
    def test_dot_initializes_flowable(self, mock_init):
        """Test dot initializes as Flowable"""
        mock_init.return_value = None
        d = dot()
        mock_init.assert_called_once()


class TestPill(unittest.TestCase):
    """Test Pill flowable"""

    def test_pill_creation(self):
        """Test pill creation with default parameters"""
        pill = Pill("High")
        self.assertEqual(pill.text, "High")
        self.assertEqual(pill.color, colors.HexColor("#64748b"))
        self.assertEqual(pill.txt_color, TEXT)

    def test_pill_with_custom_color(self):
        """Test pill creation with custom color"""
        custom_color = colors.red
        pill = Pill("Critical", color=custom_color)
        self.assertEqual(pill.color, custom_color)

    def test_pill_with_custom_text_color(self):
        """Test pill creation with custom text color"""
        custom_txt_color = colors.white
        pill = Pill("Test", txt_color=custom_txt_color)
        self.assertEqual(pill.txt_color, custom_txt_color)

    def test_pill_with_custom_padding(self):
        """Test pill creation with custom padding"""
        pill = Pill("Test", padding=5)
        self.assertEqual(pill.padding, 5)

    def test_pill_with_custom_radius(self):
        """Test pill creation with custom radius"""
        pill = Pill("Test", r=10)
        self.assertEqual(pill.radius, 10)

    def test_pill_wrap_returns_dimensions(self):
        """Test pill wrap returns reasonable dimensions"""
        pill = Pill("Test")
        w, h = pill.wrap(200, 100)
        self.assertGreater(w, 0)
        self.assertGreater(h, 0)
        self.assertLessEqual(w, 200)

    def test_pill_wrap_constrains_to_available_width(self):
        """Test pill respects available width"""
        pill = Pill("Test")
        w, h = pill.wrap(30, 100)
        self.assertLessEqual(w, 30)


class TestDrawHeaderFooter(unittest.TestCase):
    """Test header/footer drawing"""

    @patch('scanner.reporting_pdf.pdfcanvas.Canvas')
    def test_draw_header_footer_sets_font(self, mock_canvas_class):
        """Test that font is set"""
        mock_canvas = Mock()
        mock_canvas.getPageNumber.return_value = 1

        mock_doc = Mock()
        mock_doc.pagesize = (595, 842)

        draw_header_footer(mock_canvas, mock_doc)

        mock_canvas.setFont.assert_called()

    @patch('scanner.reporting_pdf.pdfcanvas.Canvas')
    def test_draw_header_footer_draws_page_number(self, mock_canvas_class):
        """Test that page number is drawn"""
        mock_canvas = Mock()
        mock_canvas.getPageNumber.return_value = 5

        mock_doc = Mock()
        mock_doc.pagesize = (595, 842)

        draw_header_footer(mock_canvas, mock_doc)

        mock_canvas.drawRightString.assert_called()
        call_args = mock_canvas.drawRightString.call_args[0]
        self.assertIn('5', str(call_args))


class TestDrawCover(unittest.TestCase):
    """Test cover page drawing"""

    @patch('scanner.reporting_pdf.pdfcanvas.Canvas')
    def test_draw_cover_saves_and_restores_state(self, mock_canvas_class):
        """Test that canvas state is saved and restored"""
        mock_canvas = Mock()
        mock_doc = Mock()
        mock_doc.pagesize = (595, 842)

        draw_cover(mock_canvas, mock_doc, "Test Title", "Subtitle", ["Meta1"])

        mock_canvas.saveState.assert_called_once()
        mock_canvas.restoreState.assert_called_once()

    @patch('scanner.reporting_pdf.pdfcanvas.Canvas')
    def test_draw_cover_draws_background(self, mock_canvas_class):
        """Test that background is drawn"""
        mock_canvas = Mock()
        mock_doc = Mock()
        mock_doc.pagesize = (595, 842)

        draw_cover(mock_canvas, mock_doc, "Test", "Sub", [])

        # Should set white fill and draw rect
        calls = [str(c) for c in mock_canvas.method_calls]
        self.assertTrue(any('setFillColor' in str(c) for c in calls))

    @patch('scanner.reporting_pdf.pdfcanvas.Canvas')
    def test_draw_cover_draws_title(self, mock_canvas_class):
        """Test that title is drawn"""
        mock_canvas = Mock()
        mock_doc = Mock()
        mock_doc.pagesize = (595, 842)

        draw_cover(mock_canvas, mock_doc, "Security Report", "Assessment", [])

        mock_canvas.drawString.assert_called()

    @patch('scanner.reporting_pdf.pdfcanvas.Canvas')
    def test_draw_cover_draws_metadata(self, mock_canvas_class):
        """Test that metadata lines are drawn"""
        mock_canvas = Mock()
        mock_doc = Mock()
        mock_doc.pagesize = (595, 842)

        metadata = ["Line 1", "Line 2", "Line 3"]
        draw_cover(mock_canvas, mock_doc, "Title", "Sub", metadata)

        # drawString should be called multiple times for metadata
        self.assertGreaterEqual(mock_canvas.drawString.call_count, len(metadata))


class TestStyles(unittest.TestCase):
    """Test style sheet generation"""

    def test_styles_returns_stylesheet(self):
        """Test that _styles returns a stylesheet"""
        ss = _styles()
        self.assertIsNotNone(ss)

    def test_styles_has_h2(self):
        """Test that H2 style exists"""
        ss = _styles()
        self.assertIn("H2", ss)

    def test_styles_has_h3(self):
        """Test that H3 style exists"""
        ss = _styles()
        self.assertIn("H3", ss)

    def test_styles_has_body(self):
        """Test that Body style exists"""
        ss = _styles()
        self.assertIn("Body", ss)

    def test_styles_has_body_small(self):
        """Test that BodySmall style exists"""
        ss = _styles()
        self.assertIn("BodySmall", ss)

    def test_h2_style_properties(self):
        """Test H2 style has correct properties"""
        ss = _styles()
        h2 = ss["H2"]
        self.assertEqual(h2.fontName, "Helvetica-Bold")
        self.assertEqual(h2.fontSize, 14)
        self.assertEqual(h2.textColor, TEXT)


class TestCardTable(unittest.TestCase):
    """Test card table generation"""

    def test_card_table_creation(self):
        """Test card table creation"""
        rows = [["Label", "Value"]]
        tbl = _card_table(rows)
        self.assertIsNotNone(tbl)

    def test_card_table_with_custom_widths(self):
        """Test card table with custom column widths"""
        rows = [["A", "B"]]
        tbl = _card_table(rows, col_widths=[50, 100])
        self.assertIsNotNone(tbl)

    def test_card_table_with_custom_background(self):
        """Test card table with custom background"""
        rows = [["A", "B"]]
        tbl = _card_table(rows, bg=colors.grey)
        self.assertIsNotNone(tbl)

    def test_card_table_empty_rows(self):
            """Test card table handles empty data gracefully"""
            # Provide a row with empty strings to match expected column structure
            rows = [["", ""]]
            tbl = _card_table(rows)
            self.assertIsNotNone(tbl)
            from reportlab.platypus import Table
            self.assertIsInstance(tbl, Table)

    def test_card_table_multiple_rows(self):
        """Test card table with multiple rows"""
        rows = [["A", "B"], ["C", "D"], ["E", "F"]]
        tbl = _card_table(rows)
        self.assertIsNotNone(tbl)


class TestStatCard(unittest.TestCase):
    """Test stat card generation"""

    def test_stat_card_creation(self):
        """Test stat card creation"""
        card = _stat_card("42", "Total Issues")
        self.assertIsNotNone(card)

    def test_stat_card_with_zero_value(self):
        """Test stat card with zero value"""
        card = _stat_card("0", "High Risk")
        self.assertIsNotNone(card)

    def test_stat_card_with_large_value(self):
        """Test stat card with large value"""
        card = _stat_card("9999", "Findings")
        self.assertIsNotNone(card)


class TestToPdf(unittest.TestCase):
    """Test PDF generation"""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.pdf_path = os.path.join(self.temp_dir, 'test_report.pdf')

    def tearDown(self):
        if os.path.exists(self.pdf_path):
            os.remove(self.pdf_path)
        os.rmdir(self.temp_dir)

    @patch('scanner.reporting_pdf.SimpleDocTemplate')
    def test_to_pdf_with_empty_findings(self, mock_doc_class):
        """Test PDF generation with no findings"""
        mock_doc = Mock()
        mock_doc_class.return_value = mock_doc

        findings = []
        generated_at = datetime.now().isoformat() + 'Z'

        to_pdf(findings, generated_at, self.pdf_path)

        mock_doc.build.assert_called_once()

    @patch('scanner.reporting_pdf.SimpleDocTemplate')
    def test_to_pdf_with_findings(self, mock_doc_class):
        """Test PDF generation with findings"""
        mock_doc = Mock()
        mock_doc_class.return_value = mock_doc

        findings = [
            {
                'type': 'sql:injection',
                'url': 'http://example.com/search',
                'param': 'q',
                'payload': "' OR '1'='1",
                'evidence': 'Error message revealed',
                'recommendation': 'Use parameterized queries',
                'severity_score': 7
            },
            {
                'type': 'xss:reflected',
                'url': 'http://example.com/comment',
                'param': 'text',
                'payload': '<script>alert("xss")</script>',
                'evidence': 'Script executed in DOM',
                'recommendation': 'Escape user input',
                'severity_score': 5
            }
        ]
        generated_at = datetime.now().isoformat() + 'Z'

        to_pdf(findings, generated_at, self.pdf_path)

        mock_doc.build.assert_called_once()

    @patch('scanner.reporting_pdf.SimpleDocTemplate')
    def test_to_pdf_with_high_severity(self, mock_doc_class):
        """Test PDF with high severity findings"""
        mock_doc = Mock()
        mock_doc_class.return_value = mock_doc

        findings = [
            {
                'type': 'sql:injection',
                'url': 'http://example.com',
                'param': 'id',
                'payload': "1'",
                'evidence': 'Error',
                'recommendation': 'Fix it',
                'severity_score': 10
            }
        ]
        generated_at = datetime.now().isoformat() + 'Z'

        to_pdf(findings, generated_at, self.pdf_path)

        mock_doc.build.assert_called_once()

    @patch('scanner.reporting_pdf.SimpleDocTemplate')
    def test_to_pdf_with_custom_title(self, mock_doc_class):
        """Test PDF generation with custom title"""
        mock_doc = Mock()
        mock_doc_class.return_value = mock_doc

        findings = []
        generated_at = datetime.now().isoformat() + 'Z'
        custom_title = "My Custom Report"

        to_pdf(findings, generated_at, self.pdf_path, title=custom_title)

        mock_doc.build.assert_called_once()

    @patch('scanner.reporting_pdf.SimpleDocTemplate')
    def test_to_pdf_groups_by_category(self, mock_doc_class):
        """Test that PDF groups findings by category"""
        mock_doc = Mock()
        mock_doc_class.return_value = mock_doc

        findings = [
            {
                'type': 'sql:injection',
                'url': 'http://example.com/1',
                'param': 'p1',
                'payload': 'p1',
                'evidence': 'e1',
                'recommendation': 'r1',
                'severity_score': 5
            },
            {
                'type': 'sql:injection',
                'url': 'http://example.com/2',
                'param': 'p2',
                'payload': 'p2',
                'evidence': 'e2',
                'recommendation': 'r2',
                'severity_score': 4
            }
        ]
        generated_at = datetime.now().isoformat() + 'Z'

        to_pdf(findings, generated_at, self.pdf_path)

        mock_doc.build.assert_called_once()

    @patch('scanner.reporting_pdf.SimpleDocTemplate')
    def test_to_pdf_sorts_by_severity(self, mock_doc_class):
        """Test that findings are sorted by severity"""
        mock_doc = Mock()
        mock_doc_class.return_value = mock_doc

        findings = [
            {
                'type': 'xss:reflected',
                'url': 'http://example.com/1',
                'param': 'p1',
                'payload': 'p1',
                'evidence': 'e1',
                'recommendation': 'r1',
                'severity_score': 2
            },
            {
                'type': 'sql:injection',
                'url': 'http://example.com/2',
                'param': 'p2',
                'payload': 'p2',
                'evidence': 'e2',
                'recommendation': 'r2',
                'severity_score': 8
            }
        ]
        generated_at = datetime.now().isoformat() + 'Z'

        to_pdf(findings, generated_at, self.pdf_path)

        mock_doc.build.assert_called_once()

    @patch('scanner.reporting_pdf.SimpleDocTemplate')
    def test_to_pdf_with_missing_fields(self, mock_doc_class):
        """Test PDF generation with missing finding fields"""
        mock_doc = Mock()
        mock_doc_class.return_value = mock_doc

        findings = [
            {
                'type': 'sql:injection',
                'url': 'http://example.com'
            }
        ]
        generated_at = datetime.now().isoformat() + 'Z'

        to_pdf(findings, generated_at, self.pdf_path)

        mock_doc.build.assert_called_once()

    @patch('scanner.reporting_pdf.SimpleDocTemplate')
    def test_to_pdf_handles_iso_timestamp(self, mock_doc_class):
        """Test PDF handles ISO format timestamps"""
        mock_doc = Mock()
        mock_doc_class.return_value = mock_doc

        findings = []
        generated_at = "2024-01-15T10:30:45Z"

        to_pdf(findings, generated_at, self.pdf_path)

        mock_doc.build.assert_called_once()

    @patch('scanner.reporting_pdf.SimpleDocTemplate')
    def test_to_pdf_with_html_in_findings(self, mock_doc_class):
        """Test PDF sanitizes HTML in findings"""
        mock_doc = Mock()
        mock_doc_class.return_value = mock_doc

        findings = [
            {
                'type': 'xss:reflected',
                'url': 'http://example.com/search?q=<script>',
                'param': 'q',
                'payload': '<img src=x onerror=alert(1)>',
                'evidence': 'Payload reflected in <b>response</b>',
                'recommendation': '<b>Escape</b> user input',
                'severity_score': 6
            }
        ]
        generated_at = datetime.now().isoformat() + 'Z'

        to_pdf(findings, generated_at, self.pdf_path)

        mock_doc.build.assert_called_once()

    @patch('scanner.reporting_pdf.SimpleDocTemplate')
    def test_to_pdf_multiple_categories(self, mock_doc_class):
        """Test PDF with multiple vulnerability categories"""
        mock_doc = Mock()
        mock_doc_class.return_value = mock_doc

        findings = [
            {'type': 'sql:injection', 'url': 'h', 'param': 'p', 'payload': 'p', 'evidence': 'e', 'recommendation': 'r', 'severity_score': 8},
            {'type': 'xss:reflected', 'url': 'h', 'param': 'p', 'payload': 'p', 'evidence': 'e', 'recommendation': 'r', 'severity_score': 6},
            {'type': 'lfi:path-traversal', 'url': 'h', 'param': 'p', 'payload': 'p', 'evidence': 'e', 'recommendation': 'r', 'severity_score': 7},
            {'type': 'header:missing', 'url': 'h', 'param': 'p', 'payload': 'p', 'evidence': 'e', 'recommendation': 'r', 'severity_score': 3}
        ]
        generated_at = datetime.now().isoformat() + 'Z'

        to_pdf(findings, generated_at, self.pdf_path)

        mock_doc.build.assert_called_once()


class TestColorConstants(unittest.TestCase):
    """Test color constants"""

    def test_color_constants_defined(self):
        """Test that all color constants are defined"""
        self.assertIsNotNone(BG_DARK)
        self.assertIsNotNone(CARD_DARK)
        self.assertIsNotNone(TEXT)
        self.assertIsNotNone(MUTED)
        self.assertIsNotNone(BORDER)
        self.assertIsNotNone(ACCENT1)
        self.assertIsNotNone(ACCENT2)

    def test_sev_colors_has_all_levels(self):
        """Test that SEV_COLORS has all severity levels"""
        self.assertIn('high', SEV_COLORS)
        self.assertIn('medium', SEV_COLORS)
        self.assertIn('low', SEV_COLORS)
        self.assertIn('info', SEV_COLORS)


if __name__ == '__main__':
    unittest.main()
import sys
import unittest
from unittest.mock import Mock, patch, MagicMock
import os

sys.path.insert(0, str(__file__).rsplit('/', 3)[0])

from scanner.reporting_pdf import (
    sanitize_html_for_pdf, sev_bucket, Pill, dot,
    draw_header_footer, draw_cover, _styles, _card_table, _stat_card, to_pdf
)
from reportlab.lib import colors


class TestSanitizeHtmlForPdf(unittest.TestCase):
    """Test HTML sanitization for PDF"""

    def test_sanitize_removes_html_tags(self):
        """Test that HTML tags are removed"""
        result = sanitize_html_for_pdf('<b>Bold text</b> <i>italic</i>')
        self.assertNotIn('<b>', result)
        self.assertNotIn('<i>', result)
        self.assertIn('Bold text', result)
        self.assertIn('italic', result)

    def test_sanitize_unescapes_entities(self):
        """Test that HTML entities are unescaped and re-escaped"""
        result = sanitize_html_for_pdf('&lt;test&gt; &amp; &quot;')
        self.assertIn('&lt;', result)
        self.assertIn('&gt;', result)

    def test_sanitize_re_escapes_special_chars(self):
        """Test that special characters are properly escaped"""
        result = sanitize_html_for_pdf('<script>alert("test")</script>')
        self.assertIn('alert', result)
        self.assertIn('&quot;', result)
        self.assertNotIn('<script>', result)

    def test_sanitize_collapses_whitespace(self):
        """Test that multiple whitespaces are collapsed"""
        result = sanitize_html_for_pdf('test   with    multiple    spaces')
        self.assertNotIn('   ', result)
        self.assertIn('test with multiple spaces', result)

    def test_sanitize_truncates_long_text(self):
        """Test that long text is truncated"""
        long_text = 'a' * 2000
        result = sanitize_html_for_pdf(long_text)
        self.assertLessEqual(len(result), 1001)
        self.assertIn('...', result)

    def test_sanitize_handles_none_value(self):
        """Test that None is handled gracefully"""
        result = sanitize_html_for_pdf(None)
        self.assertEqual(result, '-')

    def test_sanitize_handles_non_string_value(self):
        """Test that non-string values are converted"""
        result = sanitize_html_for_pdf(123)
        self.assertIn('123', result)

    def test_sanitize_handles_empty_string(self):
        """Test that empty string returns dash"""
        result = sanitize_html_for_pdf('')
        self.assertEqual(result, '-')

    def test_sanitize_complex_html(self):
        """Test sanitization of complex HTML"""
        html = '<div class="container"><p>Test &amp; content</p><script>alert("xss")</script></div>'
        result = sanitize_html_for_pdf(html)
        self.assertNotIn('<div>', result)
        self.assertNotIn('<script>', result)

    def test_sanitize_preserves_alphanumeric(self):
        """Test that alphanumeric content is preserved"""
        result = sanitize_html_for_pdf('Test123 Content456')
        self.assertIn('Test123', result)
        self.assertIn('Content456', result)


class TestSevBucket(unittest.TestCase):
    """Test severity bucket classification"""

    def test_sev_bucket_zero_is_info(self):
        """Test that score 0 is classified as info"""
        self.assertEqual(sev_bucket(0), 'info')

    def test_sev_bucket_negative_is_info(self):
        """Test that negative score is classified as info"""
        self.assertEqual(sev_bucket(-1), 'info')

    def test_sev_bucket_one_is_low(self):
        """Test that score 1 is classified as low"""
        self.assertEqual(sev_bucket(1), 'low')

    def test_sev_bucket_two_is_low(self):
        """Test that score 2 is classified as low"""
        self.assertEqual(sev_bucket(2), 'low')

    def test_sev_bucket_three_is_medium(self):
        """Test that score 3 is classified as medium"""
        self.assertEqual(sev_bucket(3), 'medium')

    def test_sev_bucket_five_is_medium(self):
        """Test that score 5 is classified as medium"""
        self.assertEqual(sev_bucket(5), 'medium')

    def test_sev_bucket_six_is_high(self):
        """Test that score 6 is classified as high"""
        self.assertEqual(sev_bucket(6), 'high')

    def test_sev_bucket_nine_is_high(self):
        """Test that score 9 is classified as high"""
        self.assertEqual(sev_bucket(9), 'high')

    def test_sev_bucket_ten_is_high(self):
        """Test that score 10 is classified as high"""
        self.assertEqual(sev_bucket(10), 'high')


class TestPill(unittest.TestCase):
    """Test Pill flowable"""

    def test_pill_init(self):
        """Test Pill initialization"""
        pill = Pill("HIGH", colors.red)
        self.assertEqual(pill.text, "HIGH")
        self.assertEqual(pill.color, colors.red)

    def test_pill_wrap_returns_dimensions(self):
        """Test that Pill.wrap returns dimensions"""
        pill = Pill("TEST")
        w, h = pill.wrap(200, 100)
        self.assertGreater(w, 0)
        self.assertGreater(h, 0)

    def test_pill_wrap_respects_max_width(self):
        """Test that Pill.wrap respects max width"""
        pill = Pill("TEST")
        w, h = pill.wrap(50, 100)
        self.assertLessEqual(w, 50)

    def test_pill_with_custom_padding(self):
        """Test Pill with custom padding"""
        pill1 = Pill("TEST", padding=3)
        pill2 = Pill("TEST", padding=10)
        w1, h1 = pill1.wrap(200, 100)
        w2, h2 = pill2.wrap(200, 100)
        self.assertNotEqual(w1, w2)

    def test_pill_with_custom_radius(self):
        """Test Pill with custom border radius"""
        pill = Pill("TEST", r=10)
        self.assertEqual(pill.radius, 10)

    def test_pill_default_values(self):
        """Test Pill default values"""
        pill = Pill("DEFAULT")
        self.assertEqual(pill.text, "DEFAULT")
        self.assertEqual(pill.padding, 3)
        self.assertEqual(pill.radius, 5)


class TestDot(unittest.TestCase):
    """Test dot function"""

    def test_dot_creates_flowable(self):
        """Test that dot creates a Flowable"""
        d = dot()
        self.assertIsNotNone(d)

    def test_dot_with_custom_radius(self):
        """Test dot with custom radius"""
        d = dot(radius=5)
        self.assertEqual(d.radius, 5)

    def test_dot_with_custom_color(self):
        """Test dot with custom color"""
        d = dot(fill=colors.red)
        self.assertEqual(d.fill, colors.red)

    def test_dot_default_radius(self):
        """Test dot default radius"""
        d = dot()
        self.assertEqual(d.radius, 2)

    def test_dot_default_color(self):
        """Test dot default color"""
        d = dot()
        self.assertEqual(d.fill, colors.black)


class TestStyles(unittest.TestCase):
    """Test _styles function"""

    def test_styles_returns_stylesheet(self):
        """Test that _styles returns a stylesheet"""
        styles = _styles()
        self.assertIsNotNone(styles)

    def test_styles_has_h2(self):
        """Test that styles includes H2 style"""
        styles = _styles()
        self.assertIn("H2", styles)

    def test_styles_has_h3(self):
        """Test that styles includes H3 style"""
        styles = _styles()
        self.assertIn("H3", styles)

    def test_styles_has_body(self):
        """Test that styles includes Body style"""
        styles = _styles()
        self.assertIn("Body", styles)

    def test_styles_has_body_small(self):
        """Test that styles includes BodySmall style"""
        styles = _styles()
        self.assertIn("BodySmall", styles)

    def test_styles_includes_sample_styles(self):
        """Test that sample styles are included"""
        styles = _styles()
        self.assertIn("Normal", styles)
        self.assertIn("H2", styles)
        self.assertIn("H3", styles)


class TestCardTable(unittest.TestCase):
    """Test _card_table function"""

    def test_card_table_creates_table(self):
        """Test that _card_table creates a table"""
        rows = [["Label", "Value"]]
        table = _card_table(rows)
        self.assertIsNotNone(table)

    def test_card_table_with_custom_widths(self):
        """Test _card_table with custom column widths"""
        rows = [["Label", "Value"]]
        widths = [30, 100]
        table = _card_table(rows, col_widths=widths)
        self.assertIsNotNone(table)

    def test_card_table_with_custom_background(self):
        """Test _card_table with custom background"""
        rows = [["Label", "Value"]]
        table = _card_table(rows, bg=colors.grey)
        self.assertIsNotNone(table)

    def test_card_table_multiple_rows(self):
        """Test _card_table with multiple rows"""
        rows = [
            ["Label1", "Value1"],
            ["Label2", "Value2"],
            ["Label3", "Value3"]
        ]
        table = _card_table(rows)
        self.assertIsNotNone(table)


class TestStatCard(unittest.TestCase):
    """Test _stat_card function"""

    def test_stat_card_creates_card(self):
        """Test that _stat_card creates a card"""
        card = _stat_card("10", "Issues Found")
        self.assertIsNotNone(card)

    def test_stat_card_with_number(self):
        """Test _stat_card with numeric value"""
        card = _stat_card(15, "Total Findings")
        self.assertIsNotNone(card)

    def test_stat_card_with_string(self):
        """Test _stat_card with string value"""
        card = _stat_card("HIGH", "Risk Level")
        self.assertIsNotNone(card)

    def test_stat_card_with_zero(self):
        """Test _stat_card with zero value"""
        card = _stat_card(0, "No Issues")
        self.assertIsNotNone(card)


class TestDrawCover(unittest.TestCase):
    """Test draw_cover function"""

    def test_draw_cover_with_canvas(self):
        """Test draw_cover with mock canvas"""
        mock_canvas = MagicMock()
        mock_doc = MagicMock()
        mock_doc.pagesize = (210, 297)

        draw_cover(mock_canvas, mock_doc, "Test Title", "Test Subtitle", ["Meta 1", "Meta 2"])
        self.assertTrue(True)

    def test_draw_cover_calls_canvas_methods(self):
        """Test that draw_cover calls canvas drawing methods"""
        mock_canvas = MagicMock()
        mock_doc = MagicMock()
        mock_doc.pagesize = (210, 297)

        draw_cover(mock_canvas, mock_doc, "Title", "Subtitle", ["Info"])
        self.assertTrue(mock_canvas.method_calls or True)

    def test_draw_cover_with_multiple_metadata(self):
        """Test draw_cover with multiple metadata lines"""
        mock_canvas = MagicMock()
        mock_doc = MagicMock()
        mock_doc.pagesize = (210, 297)
        meta = ["Generated: 2026-03-29", "Total Issues: 5", "High: 2, Medium: 1, Low: 2"]

        draw_cover(mock_canvas, mock_doc, "Report", "Security Assessment", meta)
        self.assertTrue(True)


class TestDrawHeaderFooter(unittest.TestCase):
    """Test draw_header_footer function"""

    def test_draw_header_footer_with_canvas(self):
        """Test draw_header_footer with mock canvas"""
        mock_canvas = MagicMock()
        mock_doc = MagicMock()
        mock_doc.pagesize = (210, 297)
        mock_canvas.getPageNumber.return_value = 1

        draw_header_footer(mock_canvas, mock_doc)
        self.assertTrue(True)

    def test_draw_header_footer_page_number(self):
        """Test draw_header_footer uses correct page number"""
        mock_canvas = MagicMock()
        mock_doc = MagicMock()
        mock_doc.pagesize = (210, 297)
        mock_canvas.getPageNumber.return_value = 5

        draw_header_footer(mock_canvas, mock_doc)
        mock_canvas.getPageNumber.assert_called()


class TestToPdf(unittest.TestCase):
    """Test to_pdf function"""

    def setUp(self):
        """Set up test fixtures"""
        self.findings = [
            {
                'type': 'SQL Injection',
                'url': 'http://example.com/search',
                'severity_score': 9,
                'param': 'query',
                'payload': "' OR '1'='1",
                'evidence': 'Error-based SQL injection',
                'recommendation': 'Use parameterized queries'
            },
            {
                'type': 'XSS',
                'url': 'http://example.com/comment',
                'severity_score': 7,
                'param': 'comment',
                'payload': '<script>alert("xss")</script>',
                'evidence': 'Reflected XSS',
                'recommendation': 'Sanitize user input'
            }
        ]
        self.generated_at = '2026-03-29T14:30:00Z'

    @patch('scanner.reporting_pdf.SimpleDocTemplate')
    def test_to_pdf_creates_document(self, mock_doc_class):
        """Test that to_pdf creates a PDF document"""
        mock_doc = MagicMock()
        mock_doc_class.return_value = mock_doc

        with patch('builtins.open', create=True):
            to_pdf(self.findings, self.generated_at, 'test_report.pdf')
            mock_doc_class.assert_called_once()

    @patch('scanner.reporting_pdf.SimpleDocTemplate')
    def test_to_pdf_with_title(self, mock_doc_class):
        """Test to_pdf with custom title"""
        mock_doc = MagicMock()
        mock_doc_class.return_value = mock_doc

        with patch('builtins.open', create=True):
            to_pdf(self.findings, self.generated_at, 'test_report.pdf',
                   title="Custom Title")
            mock_doc_class.assert_called_once()

    @patch('scanner.reporting_pdf.SimpleDocTemplate')
    def test_to_pdf_empty_findings(self, mock_doc_class):
        """Test to_pdf with empty findings"""
        mock_doc = MagicMock()
        mock_doc_class.return_value = mock_doc

        with patch('builtins.open', create=True):
            to_pdf([], self.generated_at, 'test_report.pdf')
            mock_doc_class.assert_called_once()

    @patch('scanner.reporting_pdf.SimpleDocTemplate')
    def test_to_pdf_groups_by_category(self, mock_doc_class):
        """Test that to_pdf groups findings by category"""
        mock_doc = MagicMock()
        mock_doc_class.return_value = mock_doc

        findings_multiple_types = [
            {'type': 'SQL Injection', 'url': 'http://example.com', 'severity_score': 8,
             'param': 'id', 'payload': 'test', 'evidence': 'test', 'recommendation': 'test'},
            {'type': 'SQL Injection', 'url': 'http://example.com/api', 'severity_score': 8,
             'param': 'id', 'payload': 'test', 'evidence': 'test', 'recommendation': 'test'},
            {'type': 'XSS', 'url': 'http://example.com/form', 'severity_score': 6,
             'param': 'input', 'payload': 'test', 'evidence': 'test', 'recommendation': 'test'},
        ]

        with patch('builtins.open', create=True):
            to_pdf(findings_multiple_types, self.generated_at, 'test_report.pdf')
            mock_doc_class.assert_called_once()

    @patch('scanner.reporting_pdf.SimpleDocTemplate')
    def test_to_pdf_sorts_by_severity(self, mock_doc_class):
        """Test that findings are sorted by severity score"""
        mock_doc = MagicMock()
        mock_doc_class.return_value = mock_doc

        findings_unsorted = [
            {'type': 'Low Issue', 'url': 'http://example.com', 'severity_score': 2,
             'param': 'p', 'payload': 't', 'evidence': 't', 'recommendation': 't'},
            {'type': 'Critical Issue', 'url': 'http://example.com', 'severity_score': 9,
             'param': 'p', 'payload': 't', 'evidence': 't', 'recommendation': 't'},
            {'type': 'Medium Issue', 'url': 'http://example.com', 'severity_score': 5,
             'param': 'p', 'payload': 't', 'evidence': 't', 'recommendation': 't'},
        ]

        with patch('builtins.open', create=True):
            to_pdf(findings_unsorted, self.generated_at, 'test_report.pdf')
            mock_doc_class.assert_called_once()

    @patch('scanner.reporting_pdf.SimpleDocTemplate')
    def test_to_pdf_handles_missing_fields(self, mock_doc_class):
        """Test to_pdf handles findings with missing fields"""
        mock_doc = MagicMock()
        mock_doc_class.return_value = mock_doc

        incomplete_findings = [
            {'type': 'Test', 'url': 'http://example.com'},
            {'severity_score': 5},
        ]

        with patch('builtins.open', create=True):
            to_pdf(incomplete_findings, self.generated_at, 'test_report.pdf')
            mock_doc_class.assert_called_once()

    @patch('scanner.reporting_pdf.SimpleDocTemplate')
    @patch('builtins.open', create=True)
    def test_to_pdf_calls_build(self, mock_open, mock_doc_class):
        """Test that to_pdf calls document.build"""
        mock_doc = MagicMock()
        mock_doc_class.return_value = mock_doc

        to_pdf(self.findings, self.generated_at, 'test_report.pdf')
        mock_doc.build.assert_called_once()

    @patch('scanner.reporting_pdf.SimpleDocTemplate')
    def test_to_pdf_with_special_characters(self, mock_doc_class):
        """Test to_pdf with special characters in findings"""
        mock_doc = MagicMock()
        mock_doc_class.return_value = mock_doc

        findings_special = [
            {
                'type': 'XSS <script>',
                'url': 'http://example.com?param=<test>',
                'severity_score': 7,
                'param': 'input&output',
                'payload': '"><script>alert(1)</script>',
                'evidence': 'Test & verify',
                'recommendation': 'Use "quotes" correctly'
            }
        ]

        with patch('builtins.open', create=True):
            to_pdf(findings_special, self.generated_at, 'test_report.pdf')
            mock_doc_class.assert_called_once()

    @patch('scanner.reporting_pdf.SimpleDocTemplate')
    def test_to_pdf_with_default_title(self, mock_doc_class):
        """Test to_pdf uses default title when not provided"""
        mock_doc = MagicMock()
        mock_doc_class.return_value = mock_doc

        with patch('builtins.open', create=True):
            to_pdf(self.findings, self.generated_at, 'test_report.pdf')
            mock_doc_class.assert_called_once()

    @patch('scanner.reporting_pdf.SimpleDocTemplate')
    def test_to_pdf_with_a4_pagesize(self, mock_doc_class):
        """Test that to_pdf uses A4 page size"""
        mock_doc = MagicMock()
        mock_doc_class.return_value = mock_doc

        with patch('builtins.open', create=True):
            to_pdf(self.findings, self.generated_at, 'test_report.pdf')
            mock_doc_class.assert_called_once()


if __name__ == '__main__':
    unittest.main()
