import unittest
import random
from unittest.case import SkipTest
from src.pysguard import DateRule, DateRangeRule, TimeRangeRule, RecurringTimeRule, TimeConstraint
from datetime import datetime, timedelta

class DateRuleTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        random.seed(datetime.now().microsecond)

    def test_date_rule_matches_exact_date(self):
        dt = datetime.today()
        r = DateRule(dt.strftime('%Y.%m.%d'))
        assert r.test(dt)

    def test_date_rule_with_wildcard_year_matches_any_year(self):
        dt = datetime.today()
        random_year = random.randint(2000, 2100)
        r = DateRule(dt.strftime('*.%m.%d'))
        assert r.test(datetime(random_year, dt.month, dt.day))

    def test_date_rule_with_wildcard_month_matches_any_month(self):
        dt = datetime.today()
        random_month = random.randint(1, 12)
        r = DateRule(dt.strftime('%Y.*.%d'))
        assert r.test(datetime(dt.year, random_month, dt.day))

    def test_date_rule_with_wildcard_day_matches_any_day(self):
        dt = datetime.today()
        random_day = random.randint(1, 28)
        r = DateRule(dt.strftime('%Y.%m.*'))
        assert r.test(datetime(dt.year, dt.month, random_day))


class TimeRuleTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls._test_time = datetime(2020, 1, 1, 13, 24, 15)

    def test_time_is_in_range_1(self):
        t = TimeRangeRule('13:24-13:25')
        assert t.test(self._test_time)

    def test_time_is_in_range_2(self):
        t = TimeRangeRule('00:00-23:59')
        assert t.test(self._test_time)

    def test_time_is_outside_range_1(self):
        t = TimeRangeRule('13:23-13:24')
        is_inside = t.test(self._test_time)
        assert not is_inside

    def test_time_is_outside_range_2(self):
        t = TimeRangeRule('13:25-13:26')
        is_inside = t.test(self._test_time)
        assert not is_inside


class DateRangeRuleTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls._test_time = datetime(2020, 11, 2)

    def test_time_is_in_range_1(self):
        t = DateRangeRule('2020.11.02-2020.11.03')
        assert t.test(self._test_time)

    def test_time_is_in_range_2(self):
        t = DateRangeRule('2020.11.01-2020.11.02')
        assert t.test(self._test_time)

    def test_time_is_outside_range_1(self):
        t = DateRangeRule('2020.10.31-2020.11.01')
        is_inside = t.test(self._test_time)
        assert not is_inside


class RecurringTimeRuleTest(unittest.TestCase):
    # Mostly testing the weekday part here as this
    # rule is a combintation of this and a TimeRangeRule

    @classmethod
    def setUpClass(cls) -> None:
        cls._weekdays = {
            'monday': datetime(2020, 11, 2, 13, 24),
            'tuesday': datetime(2020, 11, 3, 13, 24),
            'wednesday': datetime(2020, 11, 4, 13, 24),
            'thursday': datetime(2020, 11, 5, 13, 24),
            'friday': datetime(2020, 11, 6, 13, 24),
            'saturday': datetime(2020, 11, 7, 13, 24),
            'sunday': datetime(2020, 11, 8, 13, 24)
        }

    def test_wildcard_weekday_is_in_range(self):
        random.seed(datetime.now().microsecond)
        random_day = random.choice(list(self._weekdays.keys()))
        r = RecurringTimeRule('*', '13:00-14:00')
        assert r.test(self._weekdays[random_day])

    def test_each_weekday_is_in_range(self):
        for day in self._weekdays.keys():
            r = RecurringTimeRule(f'{day}s', '13:00-14:00')
            assert r.test(self._weekdays[day]), f'Unexpected result for {day}'


class TimeConstraintTest(unittest.TestCase):

    def test_time_constraint(self):
        d = datetime.now()
        if d.hour == 23 and d.minute == 59:
            raise SkipTest('Too close to midnight to assure success')
        d1 = d + timedelta(minutes=1)
        c = TimeConstraint({
            'name': 'test',
            'constraints': [
                'date   *.12.24 12:00-23:59',
                'date   *.12.24 12:00-23:59',
                'date   2006.04.14-2006.04.17',
                f'weekly * {d.strftime("%H:%M")}-{d1.strftime("%H:%M")}', # will hit this one
                'weekly   fridays 16:00-17:00'
            ]
        })
        assert c.test()
