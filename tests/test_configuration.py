import tempfile
import unittest
import os
from copy import deepcopy
from unittest.case import SkipTest
from src.pysguard import Configuration, DefaultAclEntry, ConfigurationError
from datetime import datetime, timedelta


class Environment:

    def __init__(self):
        pass

    def __enter__(self):
        os.environ['DBHOME'] = '/blacklists'
        os.environ['LOGDIR'] = tempfile.gettempdir()
        return self

    def __exit__(self, _, __, ___):
        del os.environ['DBHOME']
        del os.environ['LOGDIR']


class ConfigurationTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls._dt = datetime.now()
        if cls._dt.hour == 23 and cls._dt.minute == 59:
            raise SkipTest('Too close to midnight to assure success')
        d1 = cls._dt + timedelta(minutes=1)
        cls._config = {
            "set": {
                "dbhome": "$(DBHOME)/blacklists", #$(USERPROFILE)/Downloads/blacklists.tar/blacklists
                "logdir": "$(LOGDIR)/pyguard",
                "redirect": "http://example.com"
            },
            "time": [
                {
                    "name": "afterwork",
                    "constraints": [
                        "weekly   fridays 16:00-17:00",
                        f'weekly * {cls._dt.strftime("%H:%M")}-{d1.strftime("%H:%M")}', # will hit this one
                        "date   *.12.24 12:00-23:59",
                        "date   *.12.24 12:00-23:59",
                        "date   2006.04.14-2006.04.17"
                    ]
                }
            ],
            "sources": [
                {
                    "name": "kids",
                    "ip": [
                        "192.168.2.0-192.168.2.255",
                        "172.16.12.0/255.255.255.0",
                        "10.5.3.1/28"
                    ],
                    "user": [
                        "boy",
                        "girl"
                    ]
                }
            ],
            "destinations": [
                {
                    "name": "adult",
                    "log": "pornaccesses"
                },
                {
                    "name": "warez"
                },
                {
                    "name": "social_networks"
                }
            ],
            "acl": [
                {
                    "source": "kids",
                    "outside": {
                        "time": "afterwork",
                        "pass": "~social_networks"
                    },
                    "else": {
                        "pass": "all"
                    }
                },
                {
                    "source": "default",
                    "pass": "~adult ~warez all",
                    "redirect": "https://google.co.uk"
                },
                {
                    "source": "kids",
                    "pass": "none"
                }
            ]
        }

    @property
    def config(self):
        return deepcopy(self._config)

    def test_empty_config_produces_default_acl(self):
        c = Configuration().parse()
        entries = c.acl.entries
        assert len(entries) == 1 and isinstance(entries[0], DefaultAclEntry)

    def test_load_without_required_env_vars_throws(self):
        if 'DBHOME' in os.environ or 'LOGDIR' in os.environ:
            raise Exception("ENVIRONMENT PRESENT")
        self.assertRaises(ConfigurationError, Configuration().parse, self.config)

    def test_load_with_required_env_vars_does_not_throw(self):
        with Environment():
            Configuration().parse(self.config)

    def test_config_properties_are_all_set(self):
        with Environment():
            c = Configuration().parse(self.config)
            self.assertIsNotNone(c.setting['dbhome'])
            self.assertIsNotNone(c.setting['logdir'])
            self.assertIsNotNone(c.setting['redirect'])
