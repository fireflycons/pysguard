import unittest
from src.pysguard import SquidRequest

# https://www.patricksoftwareblog.com/python-unit-testing-structuring-your-project/

class SquidRequestTest1(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls._request = SquidRequest('1 http://example.com 1.2.3.4 GET jdoe')

    def test_request_id_is_one(self):
        assert self._request.request_id == '1', f"Unexpected: '{self._request.request_id}'"

    def test_url_is_domain(self):
        assert self._request.is_domain, f"Unexpected: '{self._request.is_domain}'"

    def test_url_is_not_ipaddress(self):
        assert not self._request.is_ipaddress, f"Unexpected: '{self._request.is_ipaddress}'"

    def test_source_ip_is_1234(self):
        assert self._request.source_ip == '1.2.3.4', f"Unexpected: '{self._request.source_ip}'"

    def test_request_method_is_get(self):
        assert self._request.method == 'GET', f"Unexpected: '{self._request.method}'"

    def test_user_is_jdoe(self):
        assert self._request.user == 'jdoe', f"Unexpected: '{self._request.user}'"

    def test_hostname_is_example_dot_com(self):
        assert self._request.host == 'example.com', f"Unexpected: '{self._request.host}'"

    def test_path_is_empty(self):
        assert not self._request.path, f"Unexpected: '{self._request.path}'"


class SquidRequestTest2(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls._request = SquidRequest('1 http://example.com/index.html 1.2.3.4 GET jdoe')

    def test_request_id_is_one(self):
        assert self._request.request_id == '1', f"Unexpected: '{self._request.request_id}'"

    def test_url_is_not_domain(self):
        assert not self._request.is_domain, f"Unexpected: '{self._request.is_domain}'"

    def test_url_is_not_ipaddress(self):
        assert not self._request.is_ipaddress, f"Unexpected: '{self._request.is_ipaddress}'"

    def test_source_ip_is_1234(self):
        assert self._request.source_ip == '1.2.3.4', f"Unexpected: '{self._request.source_ip}'"

    def test_request_method_is_get(self):
        assert self._request.method == 'GET', f"Unexpected: '{self._request.method}'"

    def test_user_is_jdoe(self):
        assert self._request.user == 'jdoe', f"Unexpected: '{self._request.user}'"

    def test_hostname_is_example_dot_com(self):
        assert self._request.host == 'example.com', f"Unexpected: '{self._request.host}'"

    def test_path_is_correct(self):
        assert self._request.path == 'index.html', f"Unexpected: '{self._request.path}'"


class SquidRequestTest3(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls._request = SquidRequest('1 http://5.6.7.8/index.html 1.2.3.4 GET jdoe')

    def test_request_id_is_one(self):
        assert self._request.request_id == '1', f"Unexpected: '{self._request.request_id}'"

    def test_url_is_not_domain(self):
        assert not self._request.is_domain, f"Unexpected: '{self._request.is_domain}'"

    def test_url_is_ipaddress(self):
        assert self._request.is_ipaddress, f"Unexpected: '{self._request.is_ipaddress}'"

    def test_source_ip_is_1234(self):
        assert self._request.source_ip == '1.2.3.4', f"Unexpected: '{self._request.source_ip}'"

    def test_request_method_is_get(self):
        assert self._request.method == 'GET', f"Unexpected: '{self._request.method}'"

    def test_user_is_jdoe(self):
        assert self._request.user == 'jdoe', f"Unexpected: '{self._request.user}'"

    def test_hostname_is_example_dot_com(self):
        assert self._request.host == '5.6.7.8', f"Unexpected: '{self._request.host}'"

    def test_path_is_correct(self):
        assert self._request.path == 'index.html', f"Unexpected: '{self._request.path}'"

