#!/usr/bin/env python3
"""
Copyright 2020 Firefly Consulting Ltd,
file: pysguard.py
No warranty of any kind.  Use at your own risk
"""

import re
from enum import Enum
import sys
import os
import stat
import socket
import yaml
import sqlite3
import argparse
import locale
from io import TextIOWrapper
from typing import List
from multiprocessing import Lock
from indexedproperty import indexedproperty
from dns.resolver import resolve
from typing import NamedTuple
from ipcalc import IP, Network
from urllib.parse import urlsplit
from datetime import datetime, time

#region Common

class InvalidRequestError(Exception):
    """
    Raised if the input (ostensibly from Squid) cannot be parsed
    """
    pass


class AbortError(Exception):
    """
    Raised if the imput stream receives the string "quit()"
    """
    pass


class ConfigurationError(Exception):
    """
    Raised for any error reasing the config file
    """
    pass


class Logger:
    """
    Very simple, but mutli-process aware logger.
    Squid can start more than one instance of this script in parallel.
    Python logger module for some reason isn't happy when this process is spawned by Squid
    """

    def __init__(self, logdir: str, always_console = False):
        """
        Constructor

        :param logdir: Directory to write log to
        :param always_console: If True write all log information to console. This will royally confuse squid if set when running as a squid child.
        """
        if logdir:
            if not (os.path.exists(logdir) and os.path.isdir(logdir)):
                os.mkdir(logdir)
            self._logfile = os.path.join(logdir, 'pysguard.log')
        else:
            self._logfile = None
        self._log_to_console = always_console or os.isatty(sys.stdin.fileno())

    def log(self, message):
        """
        Write a message to log with timestamp and PID

        :param message: Message to write
        """
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
        logmsg = f'{timestamp} [{str(os.getpid()).rjust(5)}] {message.rstrip()}'
        if self._logfile:
            with Lock():
                with open(self._logfile, "a") as f:
                    f.write(f'{logmsg}\n')
        if self._log_to_console:
            print(logmsg)

# Global logger. Initialised at program start when config has been read.
logger = None

class Util:
    """
    Static utility methods
    """

    # regex to match an IP address
    RE_IP = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')

    @staticmethod
    def is_ipaddress(host: str) -> bool:
        """
        Test whether giben input is an IP address (as opposed to a hostname.domain)

        :param host: The host/ip to test
        :return: True if the imput is an IPV4 address
        """
        return Util.RE_IP.match(host) != None

    @staticmethod
    def validate_keys(context: str, d: dict, keys: list):
        """
        Validate a dictionary as containing required set of keys

        :param context: Caller's context - i.e. class/method name
        :param d: A dict to test
        :param keys: list of key names which must exist in given dict
        """
        missing = [k for k in keys if k not in d]
        if missing:
            raise ConfigurationError(f'{context}: Missing requied attributes: {", ".join(missing)}')

class AccessResult(Enum):
    """
    Describes whether access should be granted or denied for the URL passed in by Squid.
    """
    ALLOW = 1
    DENY = 0

#endregion

#region Squid Request/Response

class SquidRequest:
    """
    Handles incoming request from Squid
    """

    # regex to match required request format and extract fields
    RE_REQUEST = re.compile(r'^(?P<id>\d+)\s+(?P<url>[^\s]+)\s+(?P<src_ip>\d+\.\d+\.\d+\.\d+)\s(?P<method>[A-Z]+)\s+(?P<user>[^\s]+)')

    def __init__(self, request:str):
        """
        Constructor

        Parse raw request and store information from it
        """
        self._request = request.strip()
        if self._request.startswith('quit()'):
            raise AbortError()
        fields = self.RE_REQUEST.search(self._request.strip())
        if not fields:
            raise InvalidRequestError('Invalid request format')
        self._request_id = fields.group('id')
        self._src_ip = fields.group('src_ip')
        self._method = fields.group('method').upper()
        self._user = fields.group('user')
        self._split_result = urlsplit(fields.group('url'))
        # Domain only in passed URL, i.e. no additional path component
        self._is_domain = self._split_result.path in ['', '/']
        self._is_ipaddress = Util.is_ipaddress(self._split_result.netloc)

    def __repr__(self):
        return f"SquidRequest('{self._request}')"

    @property
    def is_domain(self):
        """
        True if SquidRequest was for domain only (no path)
        """
        return self._is_domain

    @property
    def is_ipaddress(self):
        """
        Get a value indicating whether the host part of incoming request was an IP address
        """
        return self._is_ipaddress

    @property
    def host(self):
        """
        Gets the host part of incoming request
        """
        return self._split_result.netloc

    @property
    def path(self):
        """
        Gets the path part of incoming request
        """
        return self._split_result.path.strip('/')

    @property
    def url(self):
        """
        Gets the URL part of the incoming request (without scheme or parameters)
        """
        return self._split_result.netloc + self._split_result.path

    @property
    def request_id(self):
        """
        Gets the request ID provided by Squid. Required in the response
        """
        return self._request_id

    @property
    def formatted_request_id(self):
        """
        Gets the request ID provided by Squid formatted for logging
        """
        return f'({self._request_id})'.rjust(8)

    @property
    def source_ip(self):
        """
        Gets the source IP from the request, i.e. IP of the user's workstation
        """
        return self._src_ip

    @property
    def method(self):
        """
        Gets the HTTP request method used.
        """
        return self._method

    @property
    def user(self):
        return self._user


class SquidResponse:
    """
    Represents the response to return to Squid.
    """

    def __init__(self, request: SquidRequest = None):
        """
        Constructor

        :param request: SqudRequest built from incoming request from Squid.
        """
        if request:
            self._request_id = request.request_id
        else:
            self._request_id = None
        self._redirect = None
        self._error = None


    def redirect(self, Code=301, Url='http://example.com'):
        """
        Sets a redirection to return to squid

        :param Code: HTTP redirect code (default 301)
        :param Url: URL to redirect user to (default http://example.com)
        """
        self._redirect = f'status={Code} url={Url}'
        return self

    def error(self, message: any):
        """
        Set an error message to return to Squid

        :param message: Anything convertible to string, e.g. an Exception derivative, or just a plain string
        """
        self._error = message.__str__()
        return self

    def __str__(self) -> str:
        """
        Stringify this object - formats as a response to return to Squid.
        """
        if self._error != None:
            if self._request_id != None:
                return f'{self._request_id} BH message={self._error}\n'
            return f'BH message={self._error}\n'
        if self._redirect != None:
            return f'{self._request_id} OK {self._redirect}\n'
        return f'{self._request_id} OK\n'


#endregion

#region Source

class IPRange:
    """
    Helper class to represent a range between two IPV4 addresses,
    so you can express somthing that does not exactly fall into a CIDR range.
    """
    def __init__(self, ip1: IP, ip2: IP):
        """
        Constructor

        Store the two IPs
        """
        if ip1 > ip2:
            self._ip_lo = ip2
            self._ip_hi = ip1
        else:
            self._ip_lo = ip1
            self._ip_hi = ip2

    def __contains__(self, ip: IP) -> bool:
        """
        Test whether given IP falles within this object's range
        """
        return self._ip_lo <= ip <= self._ip_hi

    def __repr__(self):
        return f"IPRange('{self._ip_lo.__repr__()}', '{self._ip_hi.__repr__()})"


class Source:
    """
    Represents a "source" stanza from the config file
    """
    def __init__(self, source:dict):
        """
        Constructor

        Parse name, IPs and users from source configuration
        """
        Util.validate_keys('Source', source, ['name',])

        self._source = source
        self._ips = [self.__parse_ip(i) for i in source['ip']] if 'ip' in source else []
        self._domains = None
        self._users = [u for u in source['user']] if 'user' in source else []

    @property
    def name(self):
        """
        Gets the name of this source
        """
        return self._source['name']

    def __repr__(self):
        """ Not strictly __repr__ but what I want to see in debugger """
        return f'Source({self.name})'

    def __parse_ip(self, directive: str):
        """
        Parse an ip entry from the source configuration
        """
        parts = directive.split('-')
        if len(parts) > 1:
            return IPRange(IP(parts[0]), IP(parts[1]))
        if '/' in parts[0]:
            return Network(parts[0])
        return IP(parts[0])

    def test(self, request: SquidRequest) -> bool:
        """
        Test if this source matches the source (IP or user) of the given request
        Logic is OR, so return on first match

        :param request: SquidRequest object
        :return: True if user IP or name matches this source
        """
        # IP test
        src_ip = IP(request.source_ip)
        for i in self._ips:
            if type(i) is IP and i == src_ip:
                return True
            if src_ip in i:
                return True
        # User test
        return request.user in self._users


class DefaultSource(Source):
    """
    Default permissive source matched if no other source matches,
    or the configuration contains no source stanzas
    """
    def __init__(self):
        super().__init__({'name': 'default'})

    def test(self, request: SquidRequest) -> bool:
        return True


class AllSources(Source):
    """
    A subclass of Source which contains all defined sources.
    """

    def __init__(self, sources: list):
        super().__init__({'name': 'all'})
        self._all_sources = sources

    def test(self, request: SquidRequest) -> bool:
        """
        Will be true if any of the defined sources match the request
        """
        match = next((True for s in self._all_sources if s.test(request)), False)
        return match

#endregion

#region Destination

class Destination:
    """
    Represents a "destination" stanza in the configuration
    """

    def __init__(self, dest: dict):
        """
        Constructor
        """
        Util.validate_keys('Destination', dest, ['name',])
        self._dest = dest

    @staticmethod
    def all():
        """
        Factory method returning the builtin 'all' destination
        """
        return Destination({'name': 'all'})

    @staticmethod
    def none():
        """
        Factory method returning the builtin 'none' destination
        """
        return Destination({'name': 'none'})

    @property
    def name(self):
        """
        Gets the name of this source
        """
        return self._dest['name']

    @property
    def log(self):
        """
        Gets the log entry name of this source if logging confugured for it
        """
        return self._dest.get('log', None)

    def __repr__(self):
        """ Not strictly __repr__ but what I want to see in debugger """
        return f'{self.__class__.__name__}({self.name})'

#endregion

#region Time Rules

class BaseTimeRule:
    """
    Base class of time matching rules for the "time" stanza in the config file
    """

    # regex to parse a recurring time rule
    RE_RECURRING = re.compile(r'^weekly\s+(?P<day>\*|mondays|tuesdays|wednesdays|thusdays|fridays|saturdays|sundays|)\s+(?P<times>\d+:\d+-\d+:\d+)$')

    # regex to parse a date-timerange rule
    RE_DATE_DATETIME = re.compile(r'^date\s+(?P<date>(\*|\d+)\.(\*|\d+)\.(\*|\d+))(\s+(?P<times>\d+:\d+-\d+:\d+))?$')

    # regex to parse a date range rule
    RE_DATERANGE = re.compile(r'^date\s+(?P<range>(\d+\.\d+\.\d+)-(\d+\.\d+\.\d+))$')

    def __init__(self):
        """
        Constructor
        """
        self._args = ''

    @staticmethod
    def create_rule(rule: str):
        """
        Factory method to create appropriate time rule subclass given config input.

        :param rule: The raw rule definition from the config file
        :return: Subclass of this class
        """
        m = BaseTimeRule.RE_RECURRING.search(rule)
        if m:
            return RecurringTimeRule(m.group("day"), m.group("times"))
        m = BaseTimeRule.RE_DATE_DATETIME.search(rule)
        if m:
            t = m.group('times')
            if t:
                return DateTimeRule(m.group('date'), t)
            else:
                return DateRule(m.group('date'))
        m = BaseTimeRule.RE_DATERANGE.search(rule)
        if m:
            return DateRangeRule(m.group("range"))
        raise ConfigurationError("Cannot parse time rule")

    def test(self, now: datetime) -> bool:
        """
        Default implementation - alwas returns false
        """
        return False

    def __repr__(self):
        return f'{self.__class__.__name__}({self._args})'


class DateRule(BaseTimeRule):
    """
    Concrete implementation to match a single date (possibly with wildcards)
    """

    def __init__(self, dt: str):
        """
        Constructor - store date rule info
        """
        self._args = f"'{dt}'"
        self._year, self._month, self._day = dt.split('.')


    def test(self, now: datetime) -> bool:
        """
        Test whether the given date matches this rule

        :param now: The date to test, normally the date part of datetime.now().
        :return: True if the rule natches
        """
        if self._year != '*' and int(self._year) != now.year:
            return False
        if self._month != '*' and int(self._month) != now.month:
            return False
        if self._day != '*' and int(self._day) != now.day:
            return False
        return True


class TimeRangeRule(BaseTimeRule):
    """
    Concrete implementation to match a time range (within a single day)
    """
    def __init__(self, tr:str):
        """
        Constructor

        :param tr: Time range from config file entry (00:00 - 23:59)
        """
        self._args = f"'{tr}'"
        times = tr.split('-')
        if len(times) != 2:
            raise ConfigurationError(f"Invalid time range '{tr}'")
        self._start_time = time.fromisoformat(times[0])
        t2 = time.fromisoformat(times[1])
        d1 = datetime(2000, 1, 1, self._start_time.hour, self._start_time.minute, 0)
        d2 = datetime(2000, 1, 1, t2.hour, t2.minute)
        self._delta = d2 - d1

    def test(self, now: datetime) -> bool:
        """
        Test whether the given datetime matches this rule

        :param now: The time to test, normally the time part of datetime.now().
        :return: True if the rule natches
        """
        start = datetime(now.year, now.month, now.day, self._start_time.hour, self._start_time.minute, 0)
        end = start + self._delta
        return start <= now <= end


class DateTimeRule(BaseTimeRule):
    """
    Concrete implementation to match a date with time range
    """

    def __init__(self, dt: str, times: str):
        """
        Constructor

        :param dt: Date string
        :param times: Time range string
        """
        self._args = f"'{dt}','{times}'"
        self._date_rule = DateRule(dt)
        self._time_range_rule = TimeRangeRule(times)

    def test(self, now: datetime) -> bool:
        """
        Test whether the given datetime matches this rule

        :param now: The datetime to test, normally datetime.now().
        :return: True if the rule natches
        """
        if self._date_rule.test(now) == False:
            return False
        return self._time_range_rule.test(now)


class DateRangeRule(BaseTimeRule):
    """
    Concrete implementation to match a date range
    """

    def __init__(self, dr:str):
        """
        Constructor

        :param dr: Date range from config file
        """
        self._args = f"'{dr}'"
        dates = dr.split('-')
        if len(dates) != 2:
            raise ConfigurationError(f"Invalid date range '{dr}'")
        self._start_date = datetime.fromisoformat(dates[0].replace('.', '-'))
        d2 = datetime.fromisoformat(dates[1].replace('.', '-'))
        self._delta = d2 - self._start_date

    def test(self, now: datetime) -> bool:
        """
        Test whether the given date matches this rule

        :param now: The date to test, normally the date part of datetime.now().
        :return: True if the rule natches
        """
        end = self._start_date + self._delta
        return self._start_date <= now <= end


class RecurringTimeRule(BaseTimeRule):
    """
    Concrete implementation to match a recurring time rule
    """

    # Week days name to ISO day number
    ISO_WEEKDAYS = {
        '*': 0,
        'mondays': 1,
        'tuesdays': 2,
        'wednesdays': 3,
        'thursdays': 4,
        'fridays': 5,
        'saturdays': 6,
        'sundays': 7
    }

    def __init__(self, day: str, times: str):
        """
        Constructor

        :param day: Day e.g. 'mondays' or '*' for every day
        :param times: A time range
        """
        self._args = f"'{day}', '{times}'"
        try:
            self._day = self.ISO_WEEKDAYS[day]
        except KeyError:
            raise ConfigurationError(f"Invalid weekday '{day}'")
        self._time_range_rule = TimeRangeRule(times)

    def test(self, now: datetime) -> bool:
        """
        Test whether the given date matches this rule

        :param now: The date to test, normally the day and time parts of datetime.now().
        :return: True if the rule natches
        """

        # self._day will be false (i.e. zero) if parsed weekday was '*'
        if self._day and self._day != now.isoweekday():
            return False
        return self._time_range_rule.test(now)

    def __str__(self):
        return self._rr


class TimeConstraint:
    """
    Repesents a 'time' stanza from the configuration  file
    """

    def __init__(self, times: dict):
        """
        Constructor

        :param times: A time stanza from the config file
        """
        Util.validate_keys('Time', times, ['name', 'constraints'])
        self._name = times['name']
        self._rules = [BaseTimeRule.create_rule(c) for c in times['constraints']]
        pass

    @property
    def name(self):
        """
        Gets the name of this time constraint
        """
        return self._name

    def test(self) -> bool:
        """
        Test the curent datetime against all contained time rules.
        If the current time falls within any of the rules, then ALLOW
        """
        now = datetime.now()
        if next((r for r in self._rules if r.test(now) == True), False):
            return True
        return False

    def __repr__(self):
        """ Not strictly __repr__ but what I want to see in debugger """
        return f'{self.__class__.__name__}({self.name})'

#endregion

#region ACL

class PassRecord(NamedTuple):
    """
    Record returned from the test of a request against the ACL.
    """

    # Matched destination
    destination: Destination

    # Result of ACL test
    access_result: AccessResult

    # URL to redirect to on DENY result
    redirect: str


class AclEntryBase:
    """
    Base class for ACL entries
    """

    def __init__(self, acl_entry: dict, known_sources: list, known_destinations: list, default_redirect: str):
        """
        Constructor

        :param acl_entry: Content of ACL as read from config file
        :param known_souces: List of sources parsed from config file
        :param known_destinations: List of destinations parsed from config file
        :param default_redirect: Redirect URL to use if this entry does not contain a redirect
        """
        Util.validate_keys('ACL', acl_entry, ['source',])
        redirect = acl_entry.get('redirect', default_redirect)
        self._entry = acl_entry
        self._redirect = redirect
        self._source = next((s for s in known_sources if s.name == self._entry['source']), False)
        self._destinations = known_destinations
        if not self._source:
            raise ConfigurationError(f"ACL: Undefined source: '{self._entry['source']}'")

    def __repr__(self):
        return f'{self.__class__.__name__}({self.source_name})'

    @staticmethod
    def create_entry(**kwargs):
        """
        Factory method to create AclEntry subclass based on the input fields

        :Keyword Arguments:
            :AclEntry: Raw entry from config as dict
            :Sources: List of parsed sources
            :Destinations: List of parsed destinations
            :Times: List of parsed times
            :DefaultRedirect: Default redirect URL

        :returns: Appropriate subclass for type of ACL detected
        """
        Util.validate_keys('AclEntryBase.create', kwargs, ['AclEntry', 'Sources', 'Destinations', 'Times', 'DefaultRedirect'])
        if 'within' in kwargs['AclEntry'] or 'outside' in kwargs['AclEntry']:
            return TimeAclEntry(kwargs['AclEntry'], kwargs['Sources'], kwargs['Destinations'], kwargs['Times'], kwargs['DefaultRedirect'])
        else:
            return AclEntry(kwargs['AclEntry'], kwargs['Sources'], kwargs['Destinations'], kwargs['DefaultRedirect'])

    def parse_pass_list(self, pass_str: str) -> list:
        """
        Creates a list of PassRecord for each entry in 'pass: ...'

        :param pass_str: raw content of 'pass: ...' entry from config
        :returns: list of PassRecord
        """
        pass_list = []
        for p in pass_str.split():
            p = p.strip()
            if not p:
                continue
            if p.startswith('~') or p.startswith('!'):
                destination_name = p[1:]
                access_result = AccessResult.DENY
            else:
                destination_name = p
                access_result = AccessResult.ALLOW
            dest = next((d for d in self._destinations if d.name == destination_name), False)
            if dest:
                if dest.name == 'all':
                    access_result = AccessResult.ALLOW
                if dest.name == 'none':
                    access_result = AccessResult.DENY
                pass_list.append(PassRecord(dest, access_result, self._redirect))
            else:
                raise ConfigurationError(f"ACL source \'{self._entry['source']}\': Undefined destination: '{destination_name}'")
        return pass_list

    @property
    def source_name(self):
        """
        Gets the source name associated with this AclEntry
        """
        return self._entry['source']

    @property
    def source(self):
        """
        Gets the Source object associated with this AclEntry
        """
        return self._source


class TimeAclEntry(AclEntryBase):
    """
    Concrete impementation for a Time entry
    """

    def __init__(self, acl_entry: dict, known_sources: list, known_destinations: list, known_times: list, default_redirect: str):
        """
        Constructor

        :param acl_entry: Content of ACL as read from config file
        :param known_souces: List of sources parsed from config file
        :param known_destinations: List of destinations parsed from config file
        :param known_times: List of time sources parsed from config file
        :param default_redirect: Redirect URL to use if this entry does not contain a redirect
        """
        super().__init__(acl_entry, known_sources, known_destinations, default_redirect)
        within_block = acl_entry.get('within', False)
        outside_block = acl_entry.get('outside', False)
        if within_block and outside_block:
            raise ConfigurationError("time acl: Cannot specify 'within' and 'outside' together")
        else_block = acl_entry.get('else', False)
        if not else_block:
            raise ConfigurationError("time acl: Missing 'else'")
        self._op = 'within' if within_block else 'outside'
        time_block = within_block or outside_block
        Util.validate_keys(self._op, time_block, ['time', 'pass'])
        Util.validate_keys('else', else_block, ['pass',])
        self._time_source = time_block['time']
        times = [t for t in known_times if t.name == self._time_source]
        if not times:
            raise ConfigurationError(f"Undefined time '{self._time_source}'")
        self._time = times.pop(0)
        self._op_pass_List = self.parse_pass_list(time_block['pass'])
        self._else_pass_list = self.parse_pass_list(else_block['pass'])

    def __repr__(self):
        return f'{self.__class__.__name__}({self._op} {self._time_source})'

    def test(self, destinations: list) -> PassRecord:
        """
        Test this entry against the destination list.
        If no destinations match then a DENY is returned with the default redirect.

        :param destinations: List of destinations
        :returns: PassRecord
        """
        time_matched = self._time.test()
        if self._op == 'within':
            if time_matched:
                pass_list = self._op_pass_List
            else:
                pass_list = self._else_pass_list
        else: # outside
            if not time_matched:
                pass_list = self._op_pass_List
            else:
                pass_list = self._else_pass_list

        all_dest = destinations + ['all', 'none']
        return next((p for p in pass_list if p.destination.name in all_dest),
                PassRecord(Destination.none(), AccessResult.DENY, self._redirect))


class AclEntry(AclEntryBase):

    def __init__(self, acl_entry: dict, known_sources: list, known_destinations: list, default_redirect: str):
        """
        Constructor

        :param acl_entry: Content of ACL as read from config file
        :param known_souces: List of sources parsed from config file
        :param known_destinations: List of destinations parsed from config file
        :param default_redirect: Redirect URL to use if this entry does not contain a redirect
        """
        super().__init__(acl_entry, known_sources, known_destinations, default_redirect)
        Util.validate_keys('AclEntry', acl_entry, ['pass',])
        self._pass_list = self.parse_pass_list(self._entry['pass'])

    @staticmethod
    def default():
        """
        Factory method to return the default ACL entry.

        :returns: DefaultAclEntry
        """
        return DefaultAclEntry()

    def test(self, destinations: list) -> PassRecord:
        """
        Test this entry against the destination list.
        If no destinations match then a DENY is returned with the default redirect.

        :param destinations: List of destinations
        :returns: PassRecord
        """
        all_dest = destinations + ['all', 'none']
        return next((p for p in self._pass_list if p.destination.name in all_dest),
                PassRecord(Destination.none(), AccessResult.DENY, self._redirect))


class DefaultAclEntry(AclEntry):
    """
    The default ACL Entty (pass: all)
    """
    def __init__(self):
        """
        Constructor
        """
        return super().__init__({
                'source': 'default',
                'pass': 'all'
            },
            [DefaultSource()],
            [Destination.all()],
            'http://example.com')


class Acl:
    """
    Represents the acl stanza of the config file
    """

    def __init__(self, acls: List[dict]):
        """
        Constructor

        :param acls: list of acl entry dicts read from config file
        """
        self._acl_entries = acls
        self._unique_desintations = []

    def test(self, request: SquidRequest, destinations: list) -> PassRecord:
        """
        Test the incoming request against the ACL

        :param request: Parse request from Squid
        :param destinations: List of destinations (as returned by the database for given URL) to test against
        """
        # Find ACL with matching source
        entry = next((e for e in self._acl_entries if e.source.test(request)))
        if not entry:
            raise ConfigurationError("Cannot find ACL matching request source (default should have been returned)")
        return entry.test(destinations)

    @property
    def destinations(self):
        """
        Get a list of all unique destinations referenced by ACL.
        Use for DB lookup as URL can appear in multiple lists
        """
        return self._unique_desintations

    @property
    def entries(self) -> list:
        """
        Gets the list of entries within this ACL
        """
        return self._acl_entries

#endregion

#region Configuration Loader

class Configuration:
    """
    Configuration file parser
    """

    def __init__(self):
        """
        Constructor - Creates empty config object
        """
        self._config = None
        self._acl = None

    @property
    def acl(self):
        """
        Gets the configuration's ACL
        """
        return self._acl

    @indexedproperty
    def setting(self, key):
        """
        Gets the given property value from the 'set' block of the configuration

        :param key: Named subscript - name of 'set' property key
        :returns: Proerty value; else None if undefined
        """
        if key in self._props:
            return self._props[key]
        return None

    def load(self, config_file: TextIOWrapper):
        """
        Loads configuration from the given open file

        :param config_file: Open file handle to the configuration file
        :returns: This object for fluency
        """
        if not config_file:
            loc = os.path.join(os.path.dirname(__file__), 'pysguard.conf.yaml')
            config_file = open(loc, 'r')
        self._config = yaml.safe_load(config_file)
        config_file.close()
        return self

    def parse(self, config: dict = None):
        """
        Parse the configuration and construct object representation

        :param config: A dict containing a configuration to parse. If not given, then a configuration loaded by load() method will be parsed
        :returns: This object for fluency
        """
        if config:
            self._config = config
        if not self._config:
            acl_entries = [AclEntry.default()]
        else:
            acl = self._config.get('acl', False)
            if not acl:
                raise ConfigurationError("Configuration file: Missing required attribute: 'Acl'")
            props = self._config.get('set', False)
            if props:
                for k,v in props.items():
                    for m in re.findall(r'(?P<token>\$\((?P<var>[^\)]+)\))', v):
                        replacement = m[0]
                        var = m[1]
                        value = os.environ.get(var, False)
                        if not value:
                            raise ConfigurationError(f"Environment variable '{var}' not found.")
                        v = v.replace(replacement, value)
                    props[k] = v
                    pass
                self._props = props
            else:
                self._props = {}
            default_redirect = self._props.get('redirect', None)
            times = self._config.get('time', False)
            self._times = [TimeConstraint(t) for t in times] if times else []
            self._destinations = [Destination(d) for d in self._config['destinations']] if 'destinations' in self._config else []
            self._destinations.append(Destination.all())
            self._destinations.append(Destination.none())
            self._sources = [Source(s) for s in self._config['sources']] if 'sources' in self._config else []
            self._sources.append(AllSources(self._sources))
            self._sources.append(DefaultSource())
            acl_entries = [AclEntryBase.create_entry(
                    AclEntry=a,
                    Sources=self._sources,
                    Destinations=self._destinations,
                    Times=self._times,
                    DefaultRedirect=default_redirect
                ) for a in acl]
            acl_entries.sort(key = lambda a:a.source_name == 'default')
        self._acl = Acl(acl_entries)
        return self

#endregion

#region List Compilier

class ListCompiler:
    """
    Compliles squidGuard format lists to database
    """

    def __init__(self, list_location:str, lookup:bool = False):
        """
        Constructor

        :param list_location: Location of un-tarred balcklists. Expected to be in dbhome directory
        :param lookup: Not currenty supported as mega slow - DS lookup input URL to see if it still exists.
        """
        self.list_location = list_location
        self._db = Database(list_location, True)
        self._lookup = lookup
        self._added = 0
        self._rejected = 0
        self._duplicates = 0

    def __enter__(self):
        """
        Context manager entry
        """
        return self

    def __exit__(self, _, __, ___):
        """
        Context manager exit - close underlying database file
        """
        self._db.close()

    def add_category(self, category:str) -> int:
        """
        Add to the categories table of the database. A category is the name of a directory in the un-tarred blacklists

        :param category: Category name
        :return: rowid of inserted category.
        """
        with self._db.conn:
            cur = self._db.conn.cursor()
            cur.execute('select category_id from categories where category_name = ?', (category,))
            row = cur.fetchone()
            if not row:
                cur.execute('insert into categories (category_name) values (?) ', (category,))
                cur.execute('select last_insert_rowid()')
                row = cur.fetchone()
            return row[0]


    def host_exists(self, item:str) -> bool:
        """
        Lookup host in DNS
        """
        if not self._lookup:
            return True
        if item.startswith('-'):
            # Need to work out what these mean. They are invalid for domain names
            return False
        split_result = urlsplit(f'http://{item}')
        if Util.is_ipaddress(split_result.netloc):
            for port in [443, 80]:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.timeout(0.5)
                    sock.connect((split_result.netloc, port))
                    sock.close()
                    return True
                except:
                    pass
            return False
        else:
            try:
                resolve(split_result.netloc)
                return True
            except:
                return False


    def compile_entity(self, filepath:str, entity: str, category_id: int):
        """
        Compile a blacklist entity - either domains or urls

        :param filepath: Path to list
        :param entity: Entity name, either 'domain' or 'url'
        :param category_id: The ID (primary key) of the category returned by add_category()
        """
        if not os.path.exists(filepath):
            return 0
        with open(filepath, 'r') as f:
            added = 0
            with self._db.conn:
                cur = self._db.conn.cursor()
                item = f.readline().strip()
                while item:
                    if self._lookup and not self.host_exists(item):
                        self._rejected += 1
                    else:
                        cur.execute(f'select 1 from {entity}s where {entity} = ? and category_id = ?', (item, category_id))
                        if not cur.fetchone():
                            self._added += 1
                            cur.execute(f'insert into {entity}s ({entity}, category_id) values (?, ?)', (item, category_id))
                        else:
                            self._duplicates += 1
                    if (self._duplicates + self._added + self._rejected) % 10000 == 0:
                        logger.log(f'Processed: {(self._duplicates + self._added + self._rejected):n}')
                    item = f.readline().strip()


    def compile(self):
        """
        Compiles the database based on information passed to constructor.
        """
        for category in os.listdir(self.list_location):
            absolute = os.path.join(self.list_location, category)
            st = os.lstat(absolute)
            stat.S_ISDIR(st.st_mode)
            if not (stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode)):
                continue
            domains = os.path.join(absolute, 'domains')
            urls = os.path.join(absolute, 'urls')
            if not (os.path.exists(domains) or os.path.exists(urls)):
                continue
            logger.log(f'Processing {category} ...')
            category_id = self.add_category(category)
            self.compile_entity(domains, 'domain', category_id)
            self.compile_entity(urls, 'url', category_id)
        logger.log(f'{self._added:n} unique records added')

#endregion

#region Database

class Database:
    """
    sqlite3 operations
    """

    # Schema to create the database
    CREATE_SCHEMA = """

    create table if not exists categories (
        category_id integer primary key AUTOINCREMENT,
        category_name text
    );

    create table if not exists domains (
        domain_id integer primary key,
        category_id integer,
        domain text,
        foreign key(category_id) references categories(category_id)
    );

    create unique index if not exists domain_category on domains (domain, category_id);

    create table if not exists urls (
        url_id integer primary key,
        category_id integer,
        url text,
        foreign key(category_id) references categories(category_id)
    );

    create unique index if not exists url_category on urls (url, category_id);
    """


    def __init__(self, location:str, init_db = False):
        """
        Constructor

        :param: location: Location for database file - set by 'dbhome' in config
        :param init_db: If True, dump any existing database and recreate.
        """
        dbfile = os.path.join(location, "pyguard.db")
        if init_db and os.path.exists(dbfile):
            logger.log("Init Database")
            os.unlink(dbfile)
        self._conn = sqlite3.connect(dbfile)
        with self._conn:
            self._conn.executescript(self.CREATE_SCHEMA)

    def __enter__(self):
        """
        Context manager entry
        """
        return self

    def __exit__(self, _, __, ___):
        """
        Context manager exit - close database file
        """
        self.close()

    @property
    def conn(self):
        """
        Provide database connection handle
        """
        return self._conn


    def close(self):
        """
        Close database file
        """
        self.conn.close()


    def lookup(self, request: SquidRequest, acl:Acl) -> PassRecord:
        """
        Look up a URL in the database. If a category match is found, test returned categories against ACL

        :param request: REquest object built from Squid input data
        :param acl: ACL from configuration to test db result against
        :return: PassRecord descibing the matched source and the action to take.
        """
        with self.conn:
            cur = self.conn.cursor()
            host_parts = request.host.split('.')
            l = len(host_parts)
            search_domains = ['.'.join(host_parts[(l-ind):]) for ind in range(l, 1, -1)]
            cur.execute(f'select d.domain, c.category_name from domains as d inner join categories as c on d.category_id = c.category_id and d.domain in ({", ".join("?" * len(search_domains))})', search_domains)
            destinations = [r[1] for r in cur.fetchall()]
            if destinations:
                logger.log(f'{request.formatted_request_id}| Match - Category: {", ".join(destinations)}')
                # Test all ACLs. If any return False, then deny
                return acl.test(request, destinations)
            if not request.is_domain:
                # Also test URL
                cur.execute('select u.url, c.category_name from urls as u inner join categories as c on u.category_id = c.category_id and u.url = ?', (request.url,))
                destinations = [r[1] for r in cur.fetchall()]
                if destinations:
                    logger.log(f'{request.formatted_request_id}| Match - Category: {", ".join(destinations)}')
                    # Test all ACLs. If any return False, then deny
                    return acl.test(request, destinations)
        return None

#endregion


def run_loop(config:Configuration, debug=False):
    """
        Keep looping and processing requests
        Request format is based on squid directive: url_rewrite_extras "%>a %>rm %un"

        :param config: Configuration object
        :param debug: If True, process one request and return
    """
    with Database(config.setting['dbhome']) as db:
        # Get first imput
        input  = sys.stdin.readline()
        while input:
            try:
                logger.log(f'Request | {input}')
                request = SquidRequest(input)
                response = SquidResponse(request)
                if request.method not in ['CONNECT', 'OPTIONS', 'TRACE', 'HEAD']:
                    # Only process requests not in above method list
                    pass_record = db.lookup(request, config.acl)
                    if pass_record != None:
                        if pass_record.access_result == AccessResult.DENY:
                            response.redirect(Url=pass_record.redirect)
                        if pass_record.destination.log:
                            logger.log(f"{request.formatted_request_id}| {pass_record.destination.name}: {pass_record.access_result}")
            except AbortError:
                # 'quit()' was entered
                break
            except InvalidRequestError as e:
                response = SquidResponse().error(e)

            logger.log(f'Response| {response}')
            # Send result
            sys.stdout.write(f'{response}')
            sys.stdout.flush()
            if debug:
                break
            # Get next input
            input = sys.stdin.readline()
        logger.log("Process | Stopped")
        return


#
# Program Entry point
#

if __name__ == '__main__':
    locale.setlocale(locale.LC_ALL, '')
    parser = argparse.ArgumentParser(description='PYSGUARD - Python SquidGuard.')
    parser.add_argument('-C', action='store_true', help='Create database')
    parser.add_argument('-c', type=argparse.FileType('r', encoding='UTF-8'), help='Path to configuration file')
    parser.add_argument('-d', action='store_true', help='Debug mode. Accept single request from pipe and exit')
    args = parser.parse_args()

    config = Configuration().load(args.c).parse()
    logger = Logger(config.setting['logdir'], (args.C or args.d))
    logger.log("Process | Started")

    if args.C:
        # Recompile sqlite database
        # TODO - support updates. Currently dump and recreate database
        with ListCompiler(config.setting['dbhome'], False) as compiler:
            compiler.compile()
        sys.exit(0)

    # Start listening for requests
    run_loop(config.setting['dbhome'], config, args.d)

