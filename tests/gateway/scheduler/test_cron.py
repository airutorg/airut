# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for the cron expression parser."""

from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo

import pytest

from airut.gateway.scheduler.cron import CronExpression


UTC = ZoneInfo("UTC")
HELSINKI = ZoneInfo("Europe/Helsinki")
NEW_YORK = ZoneInfo("America/New_York")


# ---------------------------------------------------------------------------
# CronExpression parsing tests
# ---------------------------------------------------------------------------


class TestCronExpressionParsing:
    """Tests for cron expression field parsing via the public API."""

    def test_wildcard_minute(self) -> None:
        """Wildcard expands to full range."""
        cron = CronExpression("* 0 1 1 *")
        assert cron.minutes == frozenset(range(0, 60))

    def test_single_value(self) -> None:
        """Single numeric value."""
        cron = CronExpression("5 0 1 1 *")
        assert cron.minutes == frozenset({5})

    def test_range(self) -> None:
        """Inclusive range."""
        cron = CronExpression("0 0 * * 1-5")
        assert cron.days_of_week == frozenset({1, 2, 3, 4, 5})

    def test_step_from_star(self) -> None:
        """Step from wildcard (*/N)."""
        cron = CronExpression("*/15 0 1 1 *")
        assert cron.minutes == frozenset({0, 15, 30, 45})

    def test_range_with_step(self) -> None:
        """Range with step (N-M/S)."""
        cron = CronExpression("0-30/10 0 1 1 *")
        assert cron.minutes == frozenset({0, 10, 20, 30})

    def test_value_with_step(self) -> None:
        """Single value with step (N/S) treated as N-max/S."""
        cron = CronExpression("5/10 0 1 1 *")
        assert cron.minutes == frozenset({5, 15, 25, 35, 45, 55})

    def test_list(self) -> None:
        """Comma-separated list."""
        cron = CronExpression("0 0 1,15 1 *")
        assert cron.days_of_month == frozenset({1, 15})

    def test_list_with_range(self) -> None:
        """List mixing values and ranges."""
        cron = CronExpression("0 0 1,10-12,20 1 *")
        assert cron.days_of_month == frozenset({1, 10, 11, 12, 20})

    def test_day_of_week_7_normalized(self) -> None:
        """Day-of-week 7 is normalized to 0 (Sunday)."""
        cron = CronExpression("0 0 * * 7")
        assert cron.days_of_week == frozenset({0})

    def test_day_of_week_range_end_7_error(self) -> None:
        """Range 5-7 normalizes 7→0, creating an invalid 5-0 range."""
        with pytest.raises(ValueError, match="range start 5 > end 0"):
            CronExpression("0 0 * * 5-7")

    def test_day_of_week_range_start_7_normalized(self) -> None:
        """Day-of-week 7 at range start normalizes to 0."""
        cron = CronExpression("0 0 * * 7-3")
        assert cron.days_of_week == frozenset({0, 1, 2, 3})

    def test_error_empty_element(self) -> None:
        """Empty element in list raises ValueError."""
        with pytest.raises(ValueError, match="empty element"):
            CronExpression("0 0 , 1 *")

    def test_error_value_below_range(self) -> None:
        """Value below minimum raises ValueError."""
        with pytest.raises(ValueError, match="outside 1-31"):
            CronExpression("0 0 0 1 *")

    def test_error_value_above_range(self) -> None:
        """Value above maximum raises ValueError."""
        with pytest.raises(ValueError, match="outside 0-59"):
            CronExpression("60 0 1 1 *")

    def test_error_range_outside(self) -> None:
        """Range outside allowed bounds raises ValueError."""
        with pytest.raises(ValueError, match="outside 0-23"):
            CronExpression("0 0-25 1 1 *")

    def test_error_range_inverted(self) -> None:
        """Inverted range raises ValueError."""
        with pytest.raises(ValueError, match="range start 10 > end 5"):
            CronExpression("0 10-5 1 1 *")

    def test_error_bad_step_zero_star(self) -> None:
        """Step of 0 from wildcard raises ValueError."""
        with pytest.raises(ValueError, match="step must be >= 1"):
            CronExpression("*/0 0 1 1 *")

    def test_error_bad_step_in_range(self) -> None:
        """Step of 0 in a range raises ValueError."""
        with pytest.raises(ValueError, match="step must be >= 1"):
            CronExpression("1-10/0 0 1 1 *")

    def test_error_bad_step_on_value(self) -> None:
        """Step of 0 on a single value raises ValueError."""
        with pytest.raises(ValueError, match="step must be >= 1"):
            CronExpression("5/0 0 1 1 *")

    def test_error_unparseable(self) -> None:
        """Completely invalid expression raises ValueError."""
        with pytest.raises(ValueError, match="cannot parse"):
            CronExpression("abc 0 1 1 *")

    def test_error_bad_star_step(self) -> None:
        """Non-numeric step after * raises ValueError."""
        with pytest.raises(ValueError, match="bad step"):
            CronExpression("*/abc 0 1 1 *")

    def test_value_with_step_below_range(self) -> None:
        """Value with step below minimum raises ValueError."""
        with pytest.raises(ValueError, match="outside 1-31"):
            CronExpression("0 0 0/5 1 *")

    def test_value_with_step_above_range(self) -> None:
        """Value with step above maximum raises ValueError."""
        with pytest.raises(ValueError, match="outside 0-23"):
            CronExpression("0 25/2 1 1 *")


# ---------------------------------------------------------------------------
# CronExpression.__init__ tests
# ---------------------------------------------------------------------------


class TestCronExpressionInit:
    """Tests for CronExpression construction and attributes."""

    def test_simple_expression(self) -> None:
        """Parse a simple expression."""
        cron = CronExpression("0 9 * * 1-5")
        assert 0 in cron.minutes
        assert 9 in cron.hours
        assert cron.days_of_month == frozenset(range(1, 32))
        assert cron.months == frozenset(range(1, 13))
        assert cron.days_of_week == frozenset({1, 2, 3, 4, 5})

    def test_every_minute(self) -> None:
        """Parse '* * * * *'."""
        cron = CronExpression("* * * * *")
        assert cron.minutes == frozenset(range(0, 60))
        assert cron.hours == frozenset(range(0, 24))

    def test_dom_restricted_tracking(self) -> None:
        """dom_restricted is True when day-of-month is not *."""
        cron = CronExpression("0 0 1,15 * *")
        assert cron.dom_restricted is True
        assert cron.dow_restricted is False

    def test_dow_restricted_tracking(self) -> None:
        """dow_restricted is True when day-of-week is not *."""
        cron = CronExpression("0 0 * * 1-5")
        assert cron.dom_restricted is False
        assert cron.dow_restricted is True

    def test_both_restricted(self) -> None:
        """Both dom and dow restricted."""
        cron = CronExpression("0 0 1 * 5")
        assert cron.dom_restricted is True
        assert cron.dow_restricted is True

    def test_neither_restricted(self) -> None:
        """Neither dom nor dow restricted."""
        cron = CronExpression("0 0 * * *")
        assert cron.dom_restricted is False
        assert cron.dow_restricted is False

    def test_too_few_fields(self) -> None:
        """Fewer than 5 fields raises ValueError."""
        with pytest.raises(ValueError, match="exactly 5 fields"):
            CronExpression("* * *")

    def test_too_many_fields(self) -> None:
        """More than 5 fields raises ValueError."""
        with pytest.raises(ValueError, match="exactly 5 fields"):
            CronExpression("* * * * * *")

    def test_repr(self) -> None:
        """Repr shows the original expression."""
        cron = CronExpression("0 9 * * 1-5")
        assert repr(cron) == "CronExpression('0 9 * * 1-5')"


# ---------------------------------------------------------------------------
# CronExpression._day_matches tests
# ---------------------------------------------------------------------------


class TestDayMatches:
    """Tests for day matching with OR semantics."""

    def test_only_dom_restricted(self) -> None:
        """Only dom restricted: dom must match, dow always matches."""
        cron = CronExpression("0 0 15 * *")
        # day=15 matches dom
        assert cron._day_matches(15, 3) is True
        # day=10 doesn't match dom
        assert cron._day_matches(10, 3) is False

    def test_only_dow_restricted(self) -> None:
        """Only dow restricted: dow must match, dom always matches."""
        cron = CronExpression("0 0 * * 1")
        # weekday=1 (Monday) matches dow
        assert cron._day_matches(5, 1) is True
        # weekday=3 (Wednesday) doesn't match dow
        assert cron._day_matches(5, 3) is False

    def test_both_restricted_or_semantics(self) -> None:
        """Both restricted: OR semantics (either matching is enough)."""
        cron = CronExpression("0 0 1 * 5")  # 1st of month OR Friday
        # day=1 matches dom (regardless of dow)
        assert cron._day_matches(1, 3) is True
        # weekday=5 (Friday) matches dow (regardless of dom)
        assert cron._day_matches(15, 5) is True
        # Neither matches
        assert cron._day_matches(15, 3) is False

    def test_neither_restricted(self) -> None:
        """Neither restricted: all days match."""
        cron = CronExpression("0 0 * * *")
        assert cron._day_matches(1, 0) is True
        assert cron._day_matches(28, 6) is True


# ---------------------------------------------------------------------------
# CronExpression.next_fire_time tests
# ---------------------------------------------------------------------------


class TestNextFireTime:
    """Tests for next_fire_time computation."""

    def test_next_minute(self) -> None:
        """Every minute: fires at after + 1 minute."""
        cron = CronExpression("* * * * *")
        after = datetime(2026, 4, 3, 10, 30, 0, tzinfo=UTC)
        result = cron.next_fire_time(after, UTC)
        assert result == datetime(2026, 4, 3, 10, 31, 0, tzinfo=UTC)

    def test_truncates_seconds(self) -> None:
        """Seconds are truncated before advancing."""
        cron = CronExpression("* * * * *")
        after = datetime(2026, 4, 3, 10, 30, 45, tzinfo=UTC)
        result = cron.next_fire_time(after, UTC)
        assert result == datetime(2026, 4, 3, 10, 31, 0, tzinfo=UTC)

    def test_specific_minute(self) -> None:
        """Specific minute within the same hour."""
        cron = CronExpression("45 * * * *")
        after = datetime(2026, 4, 3, 10, 30, 0, tzinfo=UTC)
        result = cron.next_fire_time(after, UTC)
        assert result == datetime(2026, 4, 3, 10, 45, 0, tzinfo=UTC)

    def test_minute_wrap_to_next_hour(self) -> None:
        """Minute already passed: wraps to next matching hour."""
        cron = CronExpression("15 * * * *")
        after = datetime(2026, 4, 3, 10, 30, 0, tzinfo=UTC)
        result = cron.next_fire_time(after, UTC)
        assert result == datetime(2026, 4, 3, 11, 15, 0, tzinfo=UTC)

    def test_hour_wrap_to_next_day(self) -> None:
        """Hour already passed: wraps to next day."""
        cron = CronExpression("0 9 * * *")
        after = datetime(2026, 4, 3, 10, 0, 0, tzinfo=UTC)
        result = cron.next_fire_time(after, UTC)
        assert result == datetime(2026, 4, 4, 9, 0, 0, tzinfo=UTC)

    def test_weekday_filter(self) -> None:
        """Only fires on weekdays (Mon-Fri)."""
        cron = CronExpression("0 9 * * 1-5")
        # 2026-04-03 is a Friday. Next weekday fire at 09:00 is Mon 2026-04-06.
        after = datetime(2026, 4, 3, 10, 0, 0, tzinfo=UTC)
        result = cron.next_fire_time(after, UTC)
        assert result == datetime(2026, 4, 6, 9, 0, 0, tzinfo=UTC)
        assert result.weekday() == 0  # Monday

    def test_month_advancement(self) -> None:
        """Advances to matching month when current month doesn't match."""
        cron = CronExpression("0 0 1 6 *")  # 1st June at midnight
        after = datetime(2026, 7, 1, 0, 0, 0, tzinfo=UTC)
        result = cron.next_fire_time(after, UTC)
        assert result == datetime(2027, 6, 1, 0, 0, 0, tzinfo=UTC)

    def test_month_wraps_year(self) -> None:
        """Month advancement wraps to next year."""
        cron = CronExpression("0 0 1 1 *")  # 1st January
        after = datetime(2026, 2, 1, 0, 0, 0, tzinfo=UTC)
        result = cron.next_fire_time(after, UTC)
        assert result == datetime(2027, 1, 1, 0, 0, 0, tzinfo=UTC)

    def test_feb_29_leap_year(self) -> None:
        """Feb 29 fires on leap years only."""
        cron = CronExpression("0 0 29 2 *")
        after = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
        result = cron.next_fire_time(after, UTC)
        assert result == datetime(2028, 2, 29, 0, 0, 0, tzinfo=UTC)

    def test_day_31_skips_short_months(self) -> None:
        """Day 31 skips months with fewer than 31 days."""
        cron = CronExpression("0 0 31 * *")
        after = datetime(2026, 4, 1, 0, 0, 0, tzinfo=UTC)  # April has 30 days
        result = cron.next_fire_time(after, UTC)
        assert result == datetime(2026, 5, 31, 0, 0, 0, tzinfo=UTC)

    def test_dom_and_dow_or_semantics(self) -> None:
        """Both dom and dow restricted: fires on either."""
        cron = CronExpression("0 9 1 * 5")  # 1st of month OR Friday
        # 2026-04-03 is a Friday. Next fire is Friday at 09:00.
        after = datetime(2026, 4, 3, 0, 0, 0, tzinfo=UTC)
        result = cron.next_fire_time(after, UTC)
        assert result == datetime(2026, 4, 3, 9, 0, 0, tzinfo=UTC)

    def test_dom_and_dow_or_fires_on_dom(self) -> None:
        """OR semantics: fires on day-of-month match."""
        cron = CronExpression("0 9 1 * 5")  # 1st of month OR Friday
        # 2026-05-01 is a Thursday. Should fire because it's the 1st.
        after = datetime(2026, 4, 30, 10, 0, 0, tzinfo=UTC)
        result = cron.next_fire_time(after, UTC)
        assert result == datetime(2026, 5, 1, 9, 0, 0, tzinfo=UTC)

    def test_every_15_minutes(self) -> None:
        """Every 15 minutes: */15."""
        cron = CronExpression("*/15 * * * *")
        after = datetime(2026, 4, 3, 10, 16, 0, tzinfo=UTC)
        result = cron.next_fire_time(after, UTC)
        assert result == datetime(2026, 4, 3, 10, 30, 0, tzinfo=UTC)

    def test_timezone_evaluation(self) -> None:
        """Cron is evaluated in the given timezone."""
        cron = CronExpression("0 9 * * *")  # 9am Helsinki
        # 2026-04-03 09:00 Helsinki = 06:00 UTC (EEST, UTC+3)
        after = datetime(2026, 4, 3, 5, 0, 0, tzinfo=UTC)
        result = cron.next_fire_time(after, HELSINKI)
        assert result.hour == 9
        assert result.tzinfo == HELSINKI

    def test_timezone_dst_spring_forward(self) -> None:
        """Spring forward DST: 2:30 AM doesn't exist, skips to next day."""
        # US Eastern: clocks spring forward on 2026-03-08 at 2:00 AM
        cron = CronExpression("30 2 * * *")  # 2:30 AM
        after = datetime(2026, 3, 7, 23, 0, 0, tzinfo=NEW_YORK)
        result = cron.next_fire_time(after, NEW_YORK)
        # 2:30 AM doesn't exist on 2026-03-08; should skip to 2026-03-09
        assert result.day == 9
        assert result.hour == 2
        assert result.minute == 30

    def test_timezone_dst_fall_back(self) -> None:
        """Fall back DST: hour repeats, fires once at first occurrence."""
        # US Eastern: clocks fall back on 2026-11-01 at 2:00 AM
        cron = CronExpression("0 1 * * *")  # 1:00 AM
        after = datetime(2026, 10, 31, 23, 0, 0, tzinfo=NEW_YORK)
        result = cron.next_fire_time(after, NEW_YORK)
        assert result.day == 1
        assert result.hour == 1
        assert result.minute == 0

    def test_step_every_2_hours(self) -> None:
        """Every 2 hours."""
        cron = CronExpression("0 */2 * * *")
        after = datetime(2026, 4, 3, 3, 0, 0, tzinfo=UTC)
        result = cron.next_fire_time(after, UTC)
        assert result == datetime(2026, 4, 3, 4, 0, 0, tzinfo=UTC)

    def test_complex_expression(self) -> None:
        """Complex expression: 0,30 9-17 * * 1-5."""
        cron = CronExpression("0,30 9-17 * * 1-5")
        # Friday 2026-04-03 at 17:35 → next is Monday 2026-04-06 at 09:00
        after = datetime(2026, 4, 3, 17, 35, 0, tzinfo=UTC)
        result = cron.next_fire_time(after, UTC)
        assert result == datetime(2026, 4, 6, 9, 0, 0, tzinfo=UTC)

    def test_end_of_year(self) -> None:
        """Expression that fires at the start of next year."""
        cron = CronExpression("0 0 1 1 *")
        after = datetime(2026, 12, 31, 23, 59, 0, tzinfo=UTC)
        result = cron.next_fire_time(after, UTC)
        assert result == datetime(2027, 1, 1, 0, 0, 0, tzinfo=UTC)

    def test_midnight_boundary(self) -> None:
        """Midnight fires correctly."""
        cron = CronExpression("0 0 * * *")
        after = datetime(2026, 4, 3, 23, 59, 0, tzinfo=UTC)
        result = cron.next_fire_time(after, UTC)
        assert result == datetime(2026, 4, 4, 0, 0, 0, tzinfo=UTC)

    def test_strictly_after(self) -> None:
        """Next fire time is strictly after the given instant."""
        cron = CronExpression("0 9 * * *")
        # Exactly at 09:00: next fire should be tomorrow
        after = datetime(2026, 4, 3, 9, 0, 0, tzinfo=UTC)
        result = cron.next_fire_time(after, UTC)
        assert result == datetime(2026, 4, 4, 9, 0, 0, tzinfo=UTC)

    def test_after_with_seconds(self) -> None:
        """Seconds are truncated, so 09:00:30 still advances past 09:01."""
        cron = CronExpression("0 9 * * *")
        after = datetime(2026, 4, 3, 9, 0, 30, tzinfo=UTC)
        result = cron.next_fire_time(after, UTC)
        # 09:00:30 → truncate to 09:00 → +1m → 09:01 → next 09:00 is tomorrow
        assert result == datetime(2026, 4, 4, 9, 0, 0, tzinfo=UTC)

    def test_nightly_at_2am(self) -> None:
        """Common pattern: 0 2 * * * (nightly at 2 AM)."""
        cron = CronExpression("0 2 * * *")
        after = datetime(2026, 4, 3, 1, 0, 0, tzinfo=UTC)
        result = cron.next_fire_time(after, UTC)
        assert result == datetime(2026, 4, 3, 2, 0, 0, tzinfo=UTC)

    def test_hour_advancement_within_day(self) -> None:
        """When minute matches but hour doesn't, advances to next hour."""
        cron = CronExpression("0 8,12,18 * * *")
        after = datetime(2026, 4, 3, 9, 0, 0, tzinfo=UTC)
        result = cron.next_fire_time(after, UTC)
        assert result == datetime(2026, 4, 3, 12, 0, 0, tzinfo=UTC)

    def test_all_hours_passed(self) -> None:
        """All matching hours passed: goes to next day."""
        cron = CronExpression("0 8,12 * * *")
        after = datetime(2026, 4, 3, 13, 0, 0, tzinfo=UTC)
        result = cron.next_fire_time(after, UTC)
        assert result == datetime(2026, 4, 4, 8, 0, 0, tzinfo=UTC)

    def test_specific_months(self) -> None:
        """Expression with specific months."""
        cron = CronExpression("0 0 1 3,6,9,12 *")  # Quarterly
        after = datetime(2026, 4, 1, 0, 0, 0, tzinfo=UTC)
        result = cron.next_fire_time(after, UTC)
        assert result == datetime(2026, 6, 1, 0, 0, 0, tzinfo=UTC)

    def test_sunday_as_0(self) -> None:
        """Sunday as day-of-week 0."""
        cron = CronExpression("0 9 * * 0")  # Only Sundays
        # 2026-04-05 is a Sunday
        after = datetime(2026, 4, 3, 10, 0, 0, tzinfo=UTC)  # Friday
        result = cron.next_fire_time(after, UTC)
        assert result == datetime(2026, 4, 5, 9, 0, 0, tzinfo=UTC)
        assert result.weekday() == 6  # Python Sunday=6

    def test_day_of_week_7_as_sunday(self) -> None:
        """Day-of-week 7 treated as Sunday (same as 0)."""
        cron_0 = CronExpression("0 9 * * 0")
        cron_7 = CronExpression("0 9 * * 7")
        after = datetime(2026, 4, 3, 10, 0, 0, tzinfo=UTC)
        assert cron_0.next_fire_time(after, UTC) == cron_7.next_fire_time(
            after, UTC
        )

    def test_microseconds_truncated(self) -> None:
        """Microseconds are truncated."""
        cron = CronExpression("* * * * *")
        after = datetime(2026, 4, 3, 10, 30, 0, 999999, tzinfo=UTC)
        result = cron.next_fire_time(after, UTC)
        assert result.microsecond == 0
        assert result == datetime(2026, 4, 3, 10, 31, 0, tzinfo=UTC)

    def test_result_is_in_evaluation_tz(self) -> None:
        """Result timezone matches evaluation timezone."""
        cron = CronExpression("0 9 * * *")
        after = datetime(2026, 4, 3, 0, 0, 0, tzinfo=UTC)
        result = cron.next_fire_time(after, HELSINKI)
        assert str(result.tzinfo) == str(HELSINKI)

    def test_no_match_raises_runtime_error(self) -> None:
        """Expression that can never match raises RuntimeError."""
        # Feb 31 never exists
        cron = CronExpression("0 0 31 2 *")
        after = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
        with pytest.raises(RuntimeError, match="No matching fire time"):
            cron.next_fire_time(after, UTC)

    def test_day_31_in_specific_months(self) -> None:
        """Day 31 in months that have 31 days."""
        cron = CronExpression("0 0 31 1,3,5,7 *")
        after = datetime(2026, 1, 31, 1, 0, 0, tzinfo=UTC)
        result = cron.next_fire_time(after, UTC)
        assert result == datetime(2026, 3, 31, 0, 0, 0, tzinfo=UTC)

    def test_multiple_fire_times_sequential(self) -> None:
        """Calling next_fire_time repeatedly yields sequential times."""
        cron = CronExpression("0 */6 * * *")  # Every 6 hours
        t = datetime(2026, 4, 3, 0, 0, 0, tzinfo=UTC)
        expected_hours = [6, 12, 18]
        for expected_hour in expected_hours:
            t = cron.next_fire_time(t, UTC)
            assert t.hour == expected_hour
            assert t.day == 3
