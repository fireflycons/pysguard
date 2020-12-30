#!/usr/bin/env python3.8
"""
Copyright 2020 Firefly Consulting Ltd,
file: pysguard.py
No warranty of any kind.  Use at your own risk
"""

import re
from enum import Enum, IntEnum
import sys
import os
import stat
import socket
import yaml
import sqlite3
import argparse
import locale
from io import TextIOWrapper
from multiprocessing import Lock
from indexedproperty import indexedproperty
from typing import NamedTuple
from ipcalc import IP, Network
from urllib.parse import urlsplit
from datetime import datetime, time

#region Common

class InvalidRequestError(Exception):
    pass


class AbortError(Exception):
    pass


class ConfigurationError(Exception):
    pass

# TODO: Logging
# Log most messages to stderr (i.e. Squid); all messages if no logdir set.
# If a destination has a log directive and logdir is set, then create separate log file for the destination. Log the username if known
# Exceptions in file logging should be written to squid log

class LogLevel(IntEnum):

    HIGH = 1
    MED = 2
    LOW = 3
    NONE = 0


class SquidLogger:
    """
    Logger to write to Squid's cache.log
    """

    def __init__(self, verbosity: int=1):
        self._verbosity = verbosity

    def log(self, message: str, level: LogLevel=LogLevel.LOW):
        if self._verbosity == 0 or level > self._verbosity:
            return
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        logmsg = f'{timestamp} pysg| [{str(os.getpid()).rjust(5)}] {message.rstrip()}'
        # Squid captures stderr and sends it to cache.log
        sys.stderr.write(f'{logmsg}\n')
        sys.stderr.flush()


class DestinationLogger:
    """
    Logger for a destination object to create its own log file
    """

    def __init__(self, logfile: str):
        self._logfile = logfile

    def log(self, message: str):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        try:
            logmsg = f'{timestamp} | {message.rstrip()}'
            with Lock():
                with open(self._logfile, "a") as f:
                    f.write(f'{logmsg}\n')
        except:
            # Most likely directory write permission issue
            # Default to squid log
            logmsg = f'{timestamp} pysg| [{str(os.getpid()).rjust(5)}] {message.rstrip()}'
            sys.stderr.write(f'{logmsg}\n')
            sys.stderr.flush()


# Global Squid logger
logger = None

class Util:

    RE_IP = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')

    @staticmethod
    def is_ipaddress(host: str) -> bool:
        return Util.RE_IP.match(host) != None

    @staticmethod
    def validate_keys(context: str, d: dict, keys: list):
        missing = [k for k in keys if k not in d]
        if missing:
            raise ConfigurationError(f'{context}: Missing requied attributes: {", ".join(missing)}')

class AccessResult(Enum):
    ALLOW = 1
    DENY = 0

#endregion

#region Squid Request/Response

class SquidRequest:
    """
    Handles incoming request from Squid
    """

    RE_REQUEST = re.compile(r'^(?P<id>\d+)\s+(?P<url>[^\s]+)\s+(?P<src_ip>\d+\.\d+\.\d+\.\d+)\s(?P<method>[A-Z]+)\s+(?P<user>[^\s]+)')
    RE_IP = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')

    def __init__(self, request:str):
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
        self._url = fields.group('url')
        self._split_result = urlsplit(self._url)
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
        True if host part of SquidRequest was an IP address
        """
        return self._is_ipaddress

    @property
    def host(self):
        return self._split_result.netloc

    @property
    def path(self):
        return self._split_result.path.strip('/')

    @property
    def url(self):
        return self._url

    @property
    def request_id(self):
        return self._request_id

    @property
    def formatted_request_id(self):
        return f'({self._request_id})'.rjust(8)

    @property
    def source_ip(self):
        return self._src_ip

    @property
    def method(self):
        return self._method

    @property
    def user(self):
        return self._user if self._user != '-' else 'anonymous'

class SquidResponse:

    def __init__(self, request = None):
        if request:
            self._request_id = request.request_id
        else:
            self._request_id = None
        self._redirect = None
        self._error = None


    def redirect(self, **kwargs):
        code = kwargs.get('Code', 301)
        url = kwargs.get('Url', 'http://example.com')
        self._redirect = f'status={code} url={url}'
        return self

    def error(self, message):
        self._error = message.__str__()
        return self

    def __str__(self) -> str:
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

    def __init__(self, ip1: IP, ip2: IP):
        if ip1 > ip2:
            self._ip_lo = ip2
            self._ip_hi = ip1
        else:
            self._ip_lo = ip1
            self._ip_hi = ip2

    def __contains__(self, ip: IP) -> bool:
        return self._ip_lo <= ip <= self._ip_hi

    def __repr__(self):
        return f"IPRange('{self._ip_lo.__repr__()}', '{self._ip_hi.__repr__()})"


class Source:

    def __init__(self, source:dict):
        Util.validate_keys('Source', source, ['name',])

        self._source = source
        self._ips = [self._parse_ip(i) for i in source['ip']] if 'ip' in source else []
        self._domains = None
        self._users = [u for u in source['user']] if 'user' in source else []

    @property
    def name(self):
        return self._source['name']

    def __repr__(self):
        """ Not strictly __repr__ but what I want to see in debugger """
        return f'Source({self.name})'

    def _parse_ip(self, directive: str):
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

    def __init__(self):
        super().__init__({'name': 'default'})

    def test(self, request: SquidRequest) -> bool:
        return True


class AllSources(Source):

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

    def __init__(self, dest: dict, log_dir: str):
        Util.validate_keys('Destination', dest, ['name',])
        self._dest = dest
        logfile = os.path.join(log_dir, f'{dest["log"]}.log') if 'log' in dest and log_dir else None
        self._logger = DestinationLogger(logfile) if logfile else None

    @staticmethod
    def all():
        return Destination({'name': 'all'}, None)

    @staticmethod
    def none():
        return Destination({'name': 'none'}, None)

    @property
    def name(self):
        return self._dest['name']

    def log(self, message: str):
        if self._logger:
            self._logger.log(message)

    def __repr__(self):
        """ Not strictly __repr__ but what I want to see in debugger """
        return f'{self.__class__.__name__}({self.name})'

#endregion

#region Time Rules

class BaseTimeRule:

    RE_RECURRING = re.compile(r'^weekly\s+(?P<day>\*|mondays|tuesdays|wednesdays|thusdays|fridays|saturdays|sundays|)\s+(?P<times>\d+:\d+-\d+:\d+)$')
    RE_DATE_DATETIME = re.compile(r'^date\s+(?P<date>(\*|\d+)\.(\*|\d+)\.(\*|\d+))(\s+(?P<times>\d+:\d+-\d+:\d+))?$')
    RE_DATERANGE = re.compile(r'^date\s+(?P<range>(\d+\.\d+\.\d+)-(\d+\.\d+\.\d+))$')

    def __init__(self):
        self._args = ''

    @staticmethod
    def create_rule(rule: str):
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
        return False


    def __repr__(self):
        return f'{self.__class__.__name__}({self._args})'


class DateRule(BaseTimeRule):

    def __init__(self, dt: str):
        self._args = f"'{dt}'"
        self._year, self._month, self._day = dt.split('.')


    def test(self, now: datetime) -> bool:
        if self._year != '*' and int(self._year) != now.year:
            return False
        if self._month != '*' and int(self._month) != now.month:
            return False
        if self._day != '*' and int(self._day) != now.day:
            return False
        return True


class TimeRangeRule(BaseTimeRule):

    def __init__(self, tr:str):
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
        start = datetime(now.year, now.month, now.day, self._start_time.hour, self._start_time.minute, 0)
        end = start + self._delta
        return start <= now <= end


class DateTimeRule(BaseTimeRule):

    def __init__(self, dt: str, times: str):
        self._args = f"'{dt}','{times}'"
        self._date_rule = DateRule(dt)
        self._time_range_rule = TimeRangeRule(times)

    def test(self, now: datetime) -> bool:
        if self._date_rule.test(now) == False:
            return False
        return self._time_range_rule.test(now)


class DateRangeRule(BaseTimeRule):

    def __init__(self, dr:str):
        self._args = f"'{dr}'"
        dates = dr.split('-')
        if len(dates) != 2:
            raise ConfigurationError(f"Invalid date range '{dr}'")
        self._start_date = datetime.fromisoformat(dates[0].replace('.', '-'))
        d2 = datetime.fromisoformat(dates[1].replace('.', '-'))
        self._delta = d2 - self._start_date

    def test(self, now: datetime) -> bool:
        end = self._start_date + self._delta
        return self._start_date <= now <= end


class RecurringTimeRule(BaseTimeRule):

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
        self._args = f"'{day}', '{times}'"
        try:
            self._day = self.ISO_WEEKDAYS[day]
        except KeyError:
            raise ConfigurationError(f"Invalid weekday '{day}'")
        self._time_range_rule = TimeRangeRule(times)

    def test(self, now: datetime) -> bool:
        # self._day will be false (i.e. zero) if parsed weekday was '*'
        if self._day and self._day != now.isoweekday():
            return False
        return self._time_range_rule.test(now)

    def __str__(self):
        return self._rr


class TimeConstraint:

    def __init__(self, times: dict):
        Util.validate_keys('Time', times, ['name', 'constraints'])
        self._name = times['name']
        self._rules = [BaseTimeRule.create_rule(c) for c in times['constraints']]
        pass

    @property
    def name(self):
        return self._name

    def test(self) -> bool:
        """
        Test against all time rules.
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
    destination: Destination
    access_result: AccessResult
    redirect: str


class AclEntryBase:

    def __init__(self, acl_entry: dict, known_sources: list, known_destinations: list, default_redirect: str):
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
        Util.validate_keys('AclEntryBase.create', kwargs, ['AclEntry', 'Sources', 'Destinations', 'Times', 'DefaultRedirect'])
        if 'within' in kwargs['AclEntry'] or 'outside' in kwargs['AclEntry']:
            return TimeAclEntry(kwargs['AclEntry'], kwargs['Sources'], kwargs['Destinations'], kwargs['Times'], kwargs['DefaultRedirect'])
        else:
            return AclEntry(kwargs['AclEntry'], kwargs['Sources'], kwargs['Destinations'], kwargs['DefaultRedirect'])

    def parse_pass_list(self, pass_str: str, alt_redirect: str=None) -> list:
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
                pass_list.append(PassRecord(dest, access_result, alt_redirect or self._redirect))
            else:
                raise ConfigurationError(f"ACL source \'{self._entry['source']}\': Undefined destination: '{destination_name}'")
        return pass_list

    @property
    def source_name(self):
        return self._entry['source']

    @property
    def source(self):
        return self._source


class TimeAclEntry(AclEntryBase):

    def __init__(self, acl_entry: dict, known_sources: list, known_destinations: list, known_times: list, default_redirect: str):
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
        # Allow for within/outside and else to have separate redirects
        self._op_pass_List = self.parse_pass_list(time_block['pass'], time_block.get('redirect', None))
        self._else_pass_list = self.parse_pass_list(else_block['pass'], else_block.get('redirect', None))

    def __repr__(self):
        return f'{self.__class__.__name__}({self._op} {self._time_source})'

    def test(self, destinations: list) -> PassRecord:
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
        super().__init__(acl_entry, known_sources, known_destinations, default_redirect)
        Util.validate_keys('AclEntry', acl_entry, ['pass',])
        self._pass_list = self.parse_pass_list(self._entry['pass'])

    @staticmethod
    def default():
        return DefaultAclEntry()

    def test(self, destinations: list) -> PassRecord:
        """
        Test ACL entry's pass list against given destination

        :return: PassRecord if found else default None (allow never)
        """
        all_dest = destinations + ['all', 'none']
        return next((p for p in self._pass_list if p.destination.name in all_dest),
                PassRecord(Destination.none(), AccessResult.DENY, self._redirect))


class DefaultAclEntry(AclEntry):

    def __init__(self):
        return super().__init__({
                'source': 'default',
                'pass': 'all'
            },
            [DefaultSource()],
            [Destination.all()],
            'http://example.com')


class Acl:

    def __init__(self, acls: list):
        self._acl_entries = acls
        self._unique_desintations = []

    def test(self, request: SquidRequest, destinations: list) -> PassRecord:
        # Find ACL with matching source
        entry = next((e for e in self._acl_entries if e.source.test(request)), None)
        if not entry:
            raise ConfigurationError("Cannot find ACL matching request source (default should have been returned)")
        return entry.test(destinations)

    @property
    def destinations(self):
        """
        Return list of all unique destinations referenced by ACL.
        Use for DB lookup as URL can appear in multiple lists
        """
        return self._unique_desintations

    @property
    def entries(self) -> list:
        return self._acl_entries

#endregion

#region Configuration Loader

class Configuration:

    def __init__(self):
        self._config = None
        self._acl = None

    @property
    def acl(self):
        return self._acl

    @indexedproperty
    def setting(self, key):
        if key in self._props:
            return self._props[key]
        return None

    def load(self, config_file: TextIOWrapper):
        if not config_file:
            loc = os.path.join(os.path.dirname(__file__), 'pysguard.conf.yaml')
            config_file = open(loc, 'r')
        self._config = yaml.safe_load(config_file)
        config_file.close()
        return self

    def parse(self, config: dict = None):
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
                    for m in re.finditer(r'(?P<token>\$\((?P<var>[^\)]+)\))', v):
                        replacement = m.group('token')
                        var = m.group('var')
                        value = os.environ.get(var, False)
                        if not value:
                            raise ConfigurationError(f"Environment variable '{var}' not found.")
                        v = v.replace(replacement, value)
                    props[k] = v
                    pass
                self._props = props
            else:
                self._props = {}
            # Validate properties. Must have database location and default redirect.
            missing_props = [p for p in ('dbhome', 'redirect') if p not in self._props]
            if missing_props:
                raise ConfigurationError(f'Missing required configuation properties: {", ".join(missing_props)}')
            log_dir = self._props['logdir'] if 'logdir' in self._props else None
            default_redirect = self._props.get('redirect', None)
            times = self._config.get('time', False)
            self._times = [TimeConstraint(t) for t in times] if times else []
            self._destinations = [Destination(d, log_dir) for d in self._config['destinations']] if 'destinations' in self._config else []
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

    def __init__(self, list_location:str):
        self.list_location = list_location
        self._db = Database(list_location, True)
        self._added = 0
        self._rejected = 0
        self._duplicates = 0

    def __enter__(self):
        return self

    def __exit__(self, _, __, ___):
        self._db.close()

    def add_category(self, category:str) -> int:
        with self._db.conn:
            cur = self._db.conn.cursor()
            cur.execute('select category_id from categories where category_name = ?', (category,))
            row = cur.fetchone()
            if not row:
                cur.execute('insert into categories (category_name) values (?) ', (category,))
                cur.execute('select last_insert_rowid()')
                row = cur.fetchone()
            return row[0]


    def compile_entity(self, filepath:str, entity: str, category_id: int) -> int:
        if not os.path.exists(filepath):
            return 0
        with open(filepath, 'r') as f:
            added = 0
            with self._db.conn:
                cur = self._db.conn.cursor()
                item = f.readline().strip()
                while item:
                    cur.execute(f'select 1 from {entity}s where {entity} = ? and category_id = ?', (item, category_id))
                    if not cur.fetchone():
                        self._added += 1
                        cur.execute(f'insert into {entity}s ({entity}, category_id) values (?, ?)', (item, category_id))
                    else:
                        self._duplicates += 1
                    if (self._duplicates + self._added + self._rejected) % 10000 == 0:
                        logger.log(f'Processed: {(self._duplicates + self._added + self._rejected):n}', LogLevel.HIGH)
                        pass
                    item = f.readline().strip()


    def compile(self):
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
            logger.log(f'Processing {category} ...', LogLevel.HIGH)
            category_id = self.add_category(category)
            self.compile_entity(domains, 'domain', category_id)
            self.compile_entity(urls, 'url', category_id)
        logger.log(f'{self._added:n} unique records added', LogLevel.HIGH)

#endregion

#region Database

class Database:

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
        dbfile = os.path.join(location, "pyguard.db")
        if init_db and os.path.exists(dbfile):
            logger.log("Init Database", LogLevel.HIGH)
            os.unlink(dbfile)
        self._conn = sqlite3.connect(dbfile)
        with self._conn:
            self._conn.executescript(self.CREATE_SCHEMA)

    def __enter__(self):
        return self

    def __exit__(self, _, __, ___):
        self.close()

    @property
    def conn(self):
        return self._conn


    def close(self):
        self.conn.close()


    def lookup(self, request: SquidRequest, acl:Acl) -> PassRecord:
        with self.conn:
            cur = self.conn.cursor()
            host_parts = request.host.split('.')
            l = len(host_parts)
            search_domains = ['.'.join(host_parts[(l-ind):]) for ind in range(l, 1, -1)]
            cur.execute(f'select d.domain, c.category_name from domains as d inner join categories as c on d.category_id = c.category_id and d.domain in ({", ".join("?" * len(search_domains))})', search_domains)
            destinations = [r[1] for r in cur.fetchall()]
            if destinations:
                logger.log(f'{request.formatted_request_id}| Match - Category: {", ".join(destinations)}', LogLevel.LOW)
                # Test all ACLs. If any return False, then deny
                return acl.test(request, destinations)
            if not request.is_domain:
                # Also test URL
                cur.execute('select u.url, c.category_name from urls as u inner join categories as c on u.category_id = c.category_id and u.url = ?', (request.url,))
                destinations = [r[1] for r in cur.fetchall()]
                if destinations:
                    logger.log(f'{request.formatted_request_id}| Match - Category: {", ".join(destinations)}', LogLevel.LOW)
                    # Test all ACLs. If any return False, then deny
                    return acl.test(request, destinations)
        return None

#endregion


def run_loop(list_location:str, config:Configuration, debug=False):
    """
        keep looping and processing requests
        request format is based on url_rewrite_extras "%>a %>rm %un"
    """
    with Database(list_location) as db:
        input  = sys.stdin.readline()
        while input:
            try:
                logger.log(f'Request | {input}', LogLevel.MED)
                request = SquidRequest(input)
                response = SquidResponse(request)
                if request.method not in ['CONNECT', 'OPTIONS', 'TRACE', 'HEAD']:
                    pass_record = db.lookup(request, config.acl)
                    if pass_record != None:
                        pass_record.destination.log(f"{request.user} - {pass_record.destination.name}: {request.url} - {pass_record.access_result}")
                        if pass_record.access_result == AccessResult.DENY:
                            response.redirect(Url=pass_record.redirect)
            except AbortError:
                break
            except InvalidRequestError as e:
                response = SquidResponse().error(e)

            logger.log(f'Response| {response}', LogLevel.MED)
            sys.stdout.write(f'{response}')
            sys.stdout.flush()
            if debug:
                break
            input = sys.stdin.readline()
        logger.log("Process | Stopped", LogLevel.LOW)
        return


locale.setlocale(locale.LC_ALL, '')
parser = argparse.ArgumentParser(description='Python SquidGuard.')
parser.add_argument('-C', '--create-db', action='store_true', dest='create_db', help='Create database')
parser.add_argument('-c', '--config', type=argparse.FileType('r', encoding='UTF-8'), help='Path to configuation file', dest='config_file', metavar='path')
parser.add_argument('-d', '--debug', action='store_true', dest='debug', help='Debug mode. Accept single request from pipe and exit')
parser.add_argument('-v', '--vebosity', dest='verbosity', default=1, choices=[0, 1, 2, 3], help='Verbosity (0=silent...3=detailed, default=1)', metavar='level')
args = parser.parse_args()

config = Configuration().load(args.config_file).parse()
logger = SquidLogger(args.verbosity)
logger.log("Process | Started", LogLevel.LOW)

if args.create_db:
    with ListCompiler(config.setting['dbhome']) as c:
        c.compile()
    sys.exit(0)
run_loop(config.setting['dbhome'], config, args.debug)

