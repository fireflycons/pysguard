import unittest
from src.pysguard import SquidRequest, Source


class SourceTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls._request = SquidRequest('1 http://example.com 192.168.0.2 GET jdoe')

    def test_source_matches_exact_request_ip(self):
        s = Source({
            'name': 'test',
            'ip': [
                '192.168.0.2'
            ]
        })
        assert s.test(self._request)

    def test_network_matches_request_ip(self):
        s = Source({
            'name': 'test',
            'ip': [
                '192.168.0.0/24'
            ]
        })
        assert s.test(self._request)

    def test_ip_range_matches_request_ip(self):
        s = Source({
            'name': 'test',
            'ip': [
                '192.168.0.0-192.168.0.5'
            ]
        })
        assert s.test(self._request)

    def test_user_matches_request_user(self):
        s = Source({
            'name': 'test',
            'user': [
                'fredb',
                'jdoe'
            ]
        })
        assert s.test(self._request)

    def test_no_matches_when_ips_and_users_do_not_match_request(self):
        s = Source({
            'name': 'test',
            'ip': [
                '192.168.2.0-192.168.2.5',
                '10.0.0.0/8'
            ],
            'user': [
                'fredb',
                'joe'
            ]
        })
        assert not s.test(self._request)
