import sys
import unittest
from unittest.mock import Mock, patch

import requests

sys.path.insert(0, str(__file__).rsplit('/', 3)[0])

from scanner.core import Crawler, HttpClient, Orchestrator


class TestHttpClient(unittest.TestCase):
    """Test HttpClient initialization and throttling"""

    def setUp(self):
        self.client = HttpClient(rate=2.0, timeout=10)

    def test_init_default_parameters(self):
        """Test HttpClient initialization with default parameters"""
        self.assertEqual(self.client.rate, 2.0)
        self.assertEqual(self.client.timeout, 10)
        self.assertIsNotNone(self.client.sess)

    def test_init_custom_parameters(self):
        """Test HttpClient initialization with custom parameters"""
        client = HttpClient(rate=5.0, timeout=20)
        self.assertEqual(client.rate, 5.0)
        self.assertEqual(client.timeout, 20)

    def test_user_agent_header_set(self):
        """Test that User-Agent header is set correctly"""
        self.assertIn("User-Agent", self.client.sess.headers)
        self.assertEqual(self.client.sess.headers["User-Agent"], "mini-owasp-scanner/1.0")

    @patch('requests.Session.get')
    def test_get_request(self, mock_get):
        """Test GET request with throttling"""
        mock_response = Mock()
        mock_get.return_value = mock_response

        result = self.client.get('http://example.com')

        mock_get.assert_called_once()
        self.assertEqual(result, mock_response)

    @patch('requests.Session.post')
    def test_post_request(self, mock_post):
        """Test POST request with throttling"""
        mock_response = Mock()
        mock_post.return_value = mock_response

        result = self.client.post('http://example.com', data={'key': 'value'})

        mock_post.assert_called_once()
        self.assertEqual(result, mock_response)

    @patch('time.sleep')
    @patch('time.time')
    def test_throttle_applies_delay(self, mock_time, mock_sleep):
        """Test that throttle applies correct delay"""
        mock_time.side_effect = [0, 0.1, 0.1]
        client = HttpClient(rate=2.0)

        with patch.object(client.sess, 'get'):
            client.get('http://example.com')

        mock_sleep.assert_called()


class TestCrawler(unittest.TestCase):
    """Test Crawler functionality"""

    def setUp(self):
        self.base_url = 'http://example.com'
        self.http_client = Mock()
        self.crawler = Crawler(self.base_url, self.http_client, max_depth=2)

    def test_crawler_init(self):
        """Test Crawler initialization"""
        self.assertEqual(self.crawler.base, 'http://example.com')
        self.assertEqual(self.crawler.max_depth, 2)
        self.assertEqual(self.crawler.base_host, 'example.com')
        self.assertEqual(self.crawler.visited, set())
        self.assertEqual(self.crawler.params, {})
        self.assertEqual(self.crawler.forms, [])

    def test_crawler_init_strips_trailing_slash(self):
        """Test that trailing slash is removed from base URL"""
        crawler = Crawler('http://example.com/', self.http_client)
        self.assertEqual(crawler.base, 'http://example.com')

    def test_in_scope_same_host(self):
        """Test in_scope returns True for same host"""
        self.assertTrue(self.crawler.in_scope('http://example.com/page'))
        self.assertTrue(self.crawler.in_scope('http://example.com:80/page'))

    def test_in_scope_different_host(self):
        """Test in_scope returns False for different host"""
        self.assertFalse(self.crawler.in_scope('http://other.com/page'))
        self.assertFalse(self.crawler.in_scope('http://evil.com/'))

    def test_abs_join_relative_url(self):
        """Test absolute URL generation for relative URLs"""
        url = 'http://example.com/page'
        href = '/about'
        result = self.crawler._abs(url, href)
        self.assertEqual(result, 'http://example.com/about')

    def test_abs_join_relative_path(self):
        """Test absolute URL generation for relative paths"""
        url = 'http://example.com/dir/page'
        href = 'about'
        result = self.crawler._abs(url, href)
        self.assertEqual(result, 'http://example.com/dir/about')

    def test_abs_hash_route(self):
        """Test hash route URL generation"""
        url = 'http://example.com/app'
        href = '#/dashboard'
        result = self.crawler._abs(url, href)
        self.assertIn('#/dashboard', result)

    @patch('scanner.core.BeautifulSoup')
    def test_crawl_single_page(self, mock_soup):
        """Test crawling a single page"""
        mock_response = Mock()
        mock_response.text = '<html></html>'
        mock_response.headers = {'Content-Type': 'text/html'}
        self.http_client.get.return_value = mock_response

        mock_soup_instance = Mock()
        mock_soup_instance.find_all.return_value = []
        mock_soup.return_value = mock_soup_instance

        pages = self.crawler.crawl()

        self.assertGreaterEqual(len(pages), 1)
        self.http_client.get.assert_called()

    @patch('scanner.core.BeautifulSoup')
    def test_crawl_respects_max_depth(self, mock_soup):
        """Test that crawling respects max depth"""
        mock_response = Mock()
        mock_response.text = '<html><a href="/page2"></a></html>'
        mock_response.headers = {'Content-Type': 'text/html'}
        self.http_client.get.return_value = mock_response

        mock_soup_instance = Mock()
        mock_link = Mock()
        mock_link.get.return_value = '/page2'
        mock_link.__getitem__ = lambda self, key: '/page2' if key == 'href' else None

        mock_soup_instance.find_all.side_effect = [
            [mock_link],
            [],
            []
        ]
        mock_soup.return_value = mock_soup_instance

        self.crawler.max_depth = 1
        pages = self.crawler.crawl()

        self.assertGreaterEqual(len(pages), 1)

    @patch('scanner.core.BeautifulSoup')
    def test_crawl_extracts_query_parameters(self, mock_soup):
        """Test that query parameters are extracted"""
        mock_response = Mock()
        mock_response.text = '<html></html>'
        mock_response.headers = {'Content-Type': 'text/html'}
        self.http_client.get.return_value = mock_response

        mock_soup_instance = Mock()
        mock_soup_instance.find_all.return_value = []
        mock_soup.return_value = mock_soup_instance

        crawler = Crawler('http://example.com?id=123&name=test', self.http_client)
        pages = crawler.crawl()

        self.assertGreater(len(pages), 0)

        # The crawler stores params with the full URL (including query string)
        full_url = 'http://example.com?id=123&name=test'
        self.assertIn(full_url, crawler.params)
        self.assertIn('id', crawler.params[full_url])
        self.assertIn('name', crawler.params[full_url])

    @patch('scanner.core.BeautifulSoup')
    def test_crawl_extracts_forms(self, mock_soup):
        """Test that forms are extracted"""
        mock_response = Mock()
        mock_response.text = '<html><form method="POST" action="/submit"><input name="email"></form></html>'
        mock_response.headers = {'Content-Type': 'text/html'}
        self.http_client.get.return_value = mock_response

        mock_soup_instance = Mock()

        mock_form = Mock()
        mock_form.get.side_effect = lambda x, default=None: {
            'method': 'POST',
            'action': '/submit'
        }.get(x, default)

        mock_input = Mock()
        mock_input.get.side_effect = lambda x, default=None: {
            'name': 'email',
            'type': 'text',
            'value': ''
        }.get(x, default)

        mock_form.find_all.return_value = [mock_input]

        mock_soup_instance.find_all.side_effect = [
            [mock_form],
            [],
            [mock_form]
        ]
        mock_soup.return_value = mock_soup_instance

        pages = self.crawler.crawl()

        self.assertGreater(len(self.crawler.forms), 0)
        self.assertEqual(self.crawler.forms[0]['method'], 'POST')
        self.assertEqual(self.crawler.forms[0]['action'], 'http://example.com/submit')

    @patch('scanner.core.BeautifulSoup')
    def test_crawl_handles_connection_error(self, mock_soup):
        """Test that crawl handles connection errors gracefully"""
        self.http_client.get.side_effect = requests.RequestException("Connection failed")

        mock_soup_instance = Mock()
        mock_soup_instance.find_all.return_value = []
        mock_soup.return_value = mock_soup_instance

        pages = self.crawler.crawl()

        self.assertEqual(len(pages), 0)

    @patch('scanner.core.BeautifulSoup')
    def test_crawl_avoids_revisiting_urls(self, mock_soup):
        """Test that crawler avoids revisiting URLs"""
        mock_response = Mock()
        mock_response.text = '<html></html>'
        mock_response.headers = {'Content-Type': 'text/html'}
        self.http_client.get.return_value = mock_response

        mock_soup_instance = Mock()
        mock_soup_instance.find_all.return_value = []
        mock_soup.return_value = mock_soup_instance

        pages = self.crawler.crawl()
        initial_calls = self.http_client.get.call_count

        self.http_client.reset_mock()
        pages2 = self.crawler.crawl()

        self.http_client.get.assert_not_called()




class TestOrchestrator(unittest.TestCase):
    """Test Orchestrator functionality"""

    def setUp(self):
        self.base_url = 'https://example.com'
        self.orchestrator = Orchestrator(self.base_url, max_depth=1, rate=10.0)

    def test_orchestrator_init(self):
        """Test Orchestrator initialization"""
        self.assertEqual(self.orchestrator.base_url, 'https://example.com')
        self.assertIsNotNone(self.orchestrator.http)
        self.assertIsNotNone(self.orchestrator.crawler)

    def test_orchestrator_init_strips_trailing_slash(self):
        """Test that trailing slash is removed"""
        orchestrator = Orchestrator('https://example.com/')
        self.assertEqual(orchestrator.base_url, 'https://example.com')

    def test_orchestrator_init_with_auth_options(self):
        """Test Orchestrator initialization with auth options"""
        auth_opts = {'username': 'admin', 'password': 'pass'}
        orchestrator = Orchestrator(self.base_url, auth_options=auth_opts)
        self.assertEqual(orchestrator.auth_options, auth_opts)

    @patch('scanner.core.SSLTLSCheck')
    @patch('scanner.core.AuthSessionCheck')
    @patch('scanner.core.MisconfigCheck')
    @patch('scanner.core.CSRFCheck')
    @patch('scanner.core.LFICheck')
    @patch('scanner.core.XSSCheck')
    @patch('scanner.core.SQLiCheck')
    @patch('scanner.core.CookieCORSCheck')
    @patch('scanner.core.HeaderCheck')
    @patch('scanner.core.SimpleLoader')
    def test_run_returns_findings_list(self, mock_loader, mock_header, mock_cookie, mock_sqli,
                                       mock_xss, mock_lfi, mock_csrf, mock_misconfig,
                                       mock_auth, mock_ssl):
        """Test that run returns a list of findings"""
        mock_header.inspect.return_value = []
        mock_cookie.inspect.return_value = []
        mock_sqli.run.return_value = []
        mock_sqli.run_forms.return_value = []
        mock_xss.run.return_value = []
        mock_xss.run_forms.return_value = []
        mock_lfi.run.return_value = []
        mock_lfi.run_forms.return_value = []
        mock_csrf.run.return_value = []
        mock_misconfig.run.return_value = []
        mock_auth.run.return_value = []
        mock_ssl.run.return_value = []

        with patch.object(self.orchestrator.crawler, 'crawl') as mock_crawl:
            mock_response = Mock()
            mock_response.text = '<html></html>'
            mock_response.headers = {'Content-Type': 'text/html'}
            mock_crawl.return_value = [(self.base_url, mock_response)]

            findings = self.orchestrator.run()

            self.assertIsInstance(findings, list)

    @patch('scanner.core.SSLTLSCheck')
    @patch('scanner.core.AuthSessionCheck')
    @patch('scanner.core.MisconfigCheck')
    @patch('scanner.core.CSRFCheck')
    @patch('scanner.core.LFICheck')
    @patch('scanner.core.XSSCheck')
    @patch('scanner.core.SQLiCheck')
    @patch('scanner.core.CookieCORSCheck')
    @patch('scanner.core.HeaderCheck')
    @patch('scanner.core.SimpleLoader')
    def test_run_skips_ssl_check_for_http(self, mock_loader, mock_header, mock_cookie, mock_sqli,
                                          mock_xss, mock_lfi, mock_csrf, mock_misconfig,
                                          mock_auth, mock_ssl):
        """Test that SSL check is skipped for non-HTTPS URLs"""
        http_orchestrator = Orchestrator('http://example.com')

        mock_header.inspect.return_value = []
        mock_cookie.inspect.return_value = []
        mock_sqli.run.return_value = []
        mock_sqli.run_forms.return_value = []
        mock_xss.run.return_value = []
        mock_xss.run_forms.return_value = []
        mock_lfi.run.return_value = []
        mock_lfi.run_forms.return_value = []
        mock_csrf.run.return_value = []
        mock_misconfig.run.return_value = []
        mock_auth.run.return_value = []

        with patch.object(http_orchestrator.crawler, 'crawl') as mock_crawl:
            mock_response = Mock()
            mock_response.headers = {}
            mock_crawl.return_value = [('http://example.com', mock_response)]

            findings = http_orchestrator.run()

            mock_ssl.run.assert_not_called()


if __name__ == '__main__':
    unittest.main()