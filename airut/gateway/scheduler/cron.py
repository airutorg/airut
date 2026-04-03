# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Built-in 5-field cron expression parser.

Parses standard cron expressions (minute, hour, day-of-month, month,
day-of-week) and computes the next fire time relative to a given instant.
Supported syntax per field::

    *         All values in the field's range
    N         Specific value
    N-M       Inclusive range
    */S       Every S values from start of range
    N-M/S     Every S values within range
    A,B       List (elements can be values or ranges)

Day-of-week 7 is treated as 0 (Sunday), matching Vixie cron.  Named
months and days are not supported -- numeric only.

When both day-of-month and day-of-week are restricted (not ``*``), they
combine with **OR** semantics (standard Vixie cron convention).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo


# Field definitions: (name, min_value, max_value)
_FIELDS = (
    ("minute", 0, 59),
    ("hour", 0, 23),
    ("day_of_month", 1, 31),
    ("month", 1, 12),
    ("day_of_week", 0, 6),
)

#: Maximum search window for next_fire_time (handles Feb 29 edge cases).
_MAX_SEARCH_YEARS = 4

#: Pattern for a single cron field element (value, range, or step).
_ELEMENT_RE = re.compile(
    r"^(?P<star>\*)"
    r"|(?P<start>\d+)(?:-(?P<end>\d+))?"
    r"(?:/(?P<step>\d+))?$"
)


def _parse_field(expr: str, name: str, lo: int, hi: int) -> frozenset[int]:
    """Parse a single cron field into a set of matching values.

    Args:
        expr: Field expression (e.g. ``"*/15"``, ``"1-5"``, ``"0,30"``).
        name: Field name for error messages.
        lo: Minimum allowed value.
        hi: Maximum allowed value.

    Returns:
        Frozen set of integer values that match the expression.

    Raises:
        ValueError: If the expression is invalid.
    """
    values: set[int] = set()

    for element in expr.split(","):
        element = element.strip()
        if not element:
            raise ValueError(f"Invalid cron {name}: empty element in '{expr}'")

        # Handle */S (star with step)
        if element.startswith("*/"):
            step_str = element[2:]
            if not step_str.isdigit():
                raise ValueError(
                    f"Invalid cron {name}: bad step in '{element}'"
                )
            step = int(step_str)
            if step < 1:
                raise ValueError(
                    f"Invalid cron {name}: step must be >= 1 in '{element}'"
                )
            values.update(range(lo, hi + 1, step))
            continue

        if element == "*":
            values.update(range(lo, hi + 1))
            continue

        m = _ELEMENT_RE.match(element)
        if not m:
            raise ValueError(f"Invalid cron {name}: cannot parse '{element}'")

        start = int(m.group("start"))
        end_str = m.group("end")
        step_str = m.group("step")

        # Normalize day-of-week 7 → 0
        if name == "day_of_week":
            if start == 7:
                start = 0
            if end_str is not None and int(end_str) == 7:
                end_str = "0"

        if end_str is not None:
            end = int(end_str)
            if start < lo or end > hi:
                raise ValueError(
                    f"Invalid cron {name}: range {start}-{end} "
                    f"outside {lo}-{hi}"
                )
            if start > end:
                raise ValueError(
                    f"Invalid cron {name}: range start {start} > end {end}"
                )
            step = int(step_str) if step_str else 1
            if step < 1:
                raise ValueError(
                    f"Invalid cron {name}: step must be >= 1 in '{element}'"
                )
            values.update(range(start, end + 1, step))
        elif step_str is not None:
            # N/S without range: treat as N-hi/S
            step = int(step_str)
            if step < 1:
                raise ValueError(
                    f"Invalid cron {name}: step must be >= 1 in '{element}'"
                )
            if start < lo or start > hi:
                raise ValueError(
                    f"Invalid cron {name}: value {start} outside {lo}-{hi}"
                )
            values.update(range(start, hi + 1, step))
        else:
            # Single value
            if start < lo or start > hi:
                raise ValueError(
                    f"Invalid cron {name}: value {start} outside {lo}-{hi}"
                )
            values.add(start)

    return frozenset(values)


def _in_dst_gap(t: datetime) -> bool:
    """Check if a wall-clock time falls in a DST spring-forward gap.

    Converts the candidate to UTC and back.  If the round-tripped wall
    clock differs from the original, the time doesn't exist.

    Args:
        t: Timezone-aware candidate time.

    Returns:
        True if the time is in a DST gap (non-existent).
    """
    normalized = t.astimezone(UTC).astimezone(t.tzinfo)
    return normalized.hour != t.hour or normalized.minute != t.minute


class CronExpression:
    """Parsed 5-field cron expression.

    Attributes:
        minutes: Set of matching minute values (0-59).
        hours: Set of matching hour values (0-23).
        days_of_month: Set of matching day-of-month values (1-31).
        months: Set of matching month values (1-12).
        days_of_week: Set of matching day-of-week values (0-6, 0=Sun).
        dom_restricted: True if day-of-month was not ``*``.
        dow_restricted: True if day-of-week was not ``*``.
    """

    def __init__(self, expr: str) -> None:
        """Parse a cron expression.

        Args:
            expr: 5-field cron expression string.

        Raises:
            ValueError: If the expression is invalid.
        """
        fields = expr.split()
        if len(fields) != 5:
            raise ValueError(
                f"Cron expression must have exactly 5 fields, "
                f"got {len(fields)}: '{expr}'"
            )

        self.minutes = _parse_field(fields[0], *_FIELDS[0])
        self.hours = _parse_field(fields[1], *_FIELDS[1])
        self.days_of_month = _parse_field(fields[2], *_FIELDS[2])
        self.months = _parse_field(fields[3], *_FIELDS[3])
        self.days_of_week = _parse_field(fields[4], *_FIELDS[4])

        # Track whether dom/dow were wildcards for OR semantics
        self.dom_restricted = fields[2].strip() != "*"
        self.dow_restricted = fields[4].strip() != "*"

        self._expr = expr

    def _day_matches(self, day: int, weekday: int) -> bool:
        """Check if a day matches the day-of-month and day-of-week fields.

        When both fields are restricted, they combine with OR semantics
        (Vixie cron convention).  When only one is restricted, only that
        field is checked.

        Args:
            day: Day of month (1-31).
            weekday: Day of week (0-6, 0=Sunday).

        Returns:
            True if the day matches.
        """
        if self.dom_restricted and self.dow_restricted:
            # OR semantics: either field matching is sufficient
            return day in self.days_of_month or weekday in self.days_of_week
        # When only one is restricted (or neither), both must match
        return day in self.days_of_month and weekday in self.days_of_week

    def next_fire_time(self, after: datetime, tz: ZoneInfo) -> datetime:
        """Compute the next fire time strictly after the given instant.

        Args:
            after: Reference time (timezone-aware).
            tz: Timezone for cron evaluation (the cron expression is
                interpreted in this timezone).

        Returns:
            Timezone-aware datetime of the next fire (in ``tz``).

        Raises:
            RuntimeError: If no match is found within 4 years.
        """
        # Convert to evaluation timezone and advance by 1 minute,
        # truncating to the minute boundary.
        t = after.astimezone(tz)
        t = t.replace(second=0, microsecond=0) + timedelta(minutes=1)

        # Cap the search to prevent infinite loops.
        deadline = t + timedelta(days=_MAX_SEARCH_YEARS * 366)

        while t < deadline:
            # Month check
            if t.month not in self.months:
                # Advance to next matching month
                t = self._advance_month(t)
                continue

            # Day check (with OR semantics for dom+dow)
            weekday = (t.weekday() + 1) % 7  # Python Mon=0 → cron Sun=0
            if not self._day_matches(t.day, weekday):
                t = self._advance_day(t)
                continue

            # Hour check
            if t.hour not in self.hours:
                t = self._advance_hour(t)
                continue

            # Minute check
            if t.minute not in self.minutes:
                t = self._advance_minute(t)
                continue

            # All fields match — verify the time is real (not in a
            # DST gap where clocks spring forward past this hour).
            if _in_dst_gap(t):
                t = self._advance_day(t)
                continue

            return t

        raise RuntimeError(
            f"No matching fire time within {_MAX_SEARCH_YEARS} years "
            f"for cron expression '{self._expr}'"
        )

    def _advance_month(self, t: datetime) -> datetime:
        """Advance to the first day of the next matching month.

        Args:
            t: Current candidate time.

        Returns:
            New candidate with day/hour/minute reset to first matches.
        """
        year = t.year
        month = t.month

        while True:
            month += 1
            if month > 12:
                month = 1
                year += 1
            if month in self.months:
                break

        return t.replace(
            year=year,
            month=month,
            day=1,
            hour=min(self.hours),
            minute=min(self.minutes),
        )

    def _advance_day(self, t: datetime) -> datetime:
        """Advance to the next day with hour/minute reset.

        Args:
            t: Current candidate time.

        Returns:
            New candidate at next day, first matching hour and minute.
        """
        t = t.replace(
            hour=min(self.hours),
            minute=min(self.minutes),
        )
        return t + timedelta(days=1)

    def _advance_hour(self, t: datetime) -> datetime:
        """Advance to the next matching hour within the same day.

        If no matching hour remains today, advance to the next day.

        Args:
            t: Current candidate time.

        Returns:
            New candidate at next matching hour (minute reset).
        """
        next_hours = [h for h in sorted(self.hours) if h > t.hour]
        if next_hours:
            return t.replace(hour=next_hours[0], minute=min(self.minutes))
        # No matching hour left today — advance to next day
        return self._advance_day(t)

    def _advance_minute(self, t: datetime) -> datetime:
        """Advance to the next matching minute within the same hour.

        If no matching minute remains this hour, advance to the next hour.

        Args:
            t: Current candidate time.

        Returns:
            New candidate at next matching minute.
        """
        next_minutes = [m for m in sorted(self.minutes) if m > t.minute]
        if next_minutes:
            return t.replace(minute=next_minutes[0])
        # No matching minute left this hour — advance to next hour
        return self._advance_hour(t)

    def __repr__(self) -> str:
        return f"CronExpression('{self._expr}')"
