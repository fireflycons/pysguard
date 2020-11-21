import unittest
from src.pysguard import SquidRequest, SquidResponse

# https://www.patricksoftwareblog.com/python-unit-testing-structuring-your-project/

class SquidResponseTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls._request = SquidRequest('1 http://example.com 1.2.3.4 GET jdoe')
        cls._response = SquidResponse(cls._request)

    def test_01_response_is_ok_when_no_redirect(self):
        expected_response = f'{self._request.request_id} OK\n'
        assert self._response.__str__() == expected_response

    def test_02_response_is_default_redirect_when_no_redirect_set(self):
        expected_default_redirect = f'{self._request.request_id} OK status=301 url=http://example.com\n'
        self._response.redirect()
        assert self._response.__str__() == expected_default_redirect, f'Unexpected result {self._response}'

    def test_03_response_is_specific_redirect(self):
        redirect = 'https://www.google.com/'
        self._response.redirect(Url=redirect)
        expected_response = f'{self._request.request_id} OK status=301 url={redirect}\n'
        assert self._response.__str__() == expected_response

    def test_04_response_is_specific_redirect_with_code(self):
        redirect = 'https://www.google.com/'
        self._response.redirect(Url=redirect, Code=302)
        expected_response = f'{self._request.request_id} OK status=302 url={redirect}\n'
        assert self._response.__str__() == expected_response