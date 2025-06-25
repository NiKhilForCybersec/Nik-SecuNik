"""
Time Utilities - Timestamp parsing and manipulation
Handles various timestamp formats and time zone conversions
"""

from datetime import datetime, timezone, timedelta
from typing import Optional, Union, List, Tuple
import re
import pytz
from dateutil import parser as date_parser
from dateutil.tz import tzlocal, tzutc
import time
import calendar

class TimeParser:
    """Advanced timestamp parsing and manipulation"""
    
    def __init__(self):
        # Common timestamp formats
        self.formats = [
            # ISO formats
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            
            # Common log formats
            "%b %d %H:%M:%S",  # Syslog
            "%d/%b/%Y:%H:%M:%S %z",  # Apache
            "%Y/%m/%d %H:%M:%S",  # IIS
            "%d-%b-%Y %H:%M:%S",
            "%m/%d/%Y %I:%M:%S %p",  # US format with AM/PM
            
            # Epoch formats handled separately
        ]
        
        # Month name mappings
        self.month_map = {
            'jan': 1, 'feb': 2, 'mar': 3, 'apr': 4,
            'may': 5, 'jun': 6, 'jul': 7, 'aug': 8,
            'sep': 9, 'oct': 10, 'nov': 11, 'dec': 12
        }
        
        # Timezone mappings
        self.tz_map = {
            'EST': 'US/Eastern',
            'EDT': 'US/Eastern',
            'CST': 'US/Central',
            'CDT': 'US/Central',
            'MST': 'US/Mountain',
            'MDT': 'US/Mountain',
            'PST': 'US/Pacific',
            'PDT': 'US/Pacific',
            'GMT': 'UTC',
            'BST': 'Europe/London'
        }
        
    def parse_timestamp(
        self,
        timestamp: Union[str, int, float],
        timezone_str: Optional[str] = None,
        default_year: Optional[int] = None
    ) -> Optional[datetime]:
        """Parse timestamp from various formats"""
        if timestamp is None:
            return None
            
        # Handle numeric timestamps (epoch)
        if isinstance(timestamp, (int, float)):
            return self._parse_epoch(timestamp)
            
        # Handle string timestamps
        timestamp = str(timestamp).strip()
        
        if not timestamp:
            return None
            
        # Try dateutil parser first
        try:
            dt = date_parser.parse(timestamp, fuzzy=True)
            
            # Add year if missing (for syslog format)
            if default_year and dt.year == datetime.now().year and 'year' not in timestamp.lower():
                dt = dt.replace(year=default_year)
                
            # Add timezone if specified
            if timezone_str and dt.tzinfo is None:
                dt = self._add_timezone(dt, timezone_str)
                
            return dt
            
        except (ValueError, OverflowError):
            pass
            
        # Try specific formats
        for fmt in self.formats:
            try:
                dt = datetime.strptime(timestamp, fmt)
                
                # Add year for formats without year
                if '%Y' not in fmt and default_year:
                    dt = dt.replace(year=default_year)
                    
                # Add timezone
                if timezone_str and dt.tzinfo is None:
                    dt = self._add_timezone(dt, timezone_str)
                    
                return dt
                
            except ValueError:
                continue
                
        # Try custom parsing
        return self._custom_parse(timestamp, timezone_str, default_year)
        
    def _parse_epoch(self, timestamp: Union[int, float]) -> datetime:
        """Parse epoch timestamp"""
        # Detect if milliseconds or microseconds
        if timestamp > 1e11:  # Likely milliseconds
            timestamp = timestamp / 1000
        elif timestamp > 1e14:  # Likely microseconds
            timestamp = timestamp / 1000000
            
        try:
            return datetime.fromtimestamp(timestamp, tz=timezone.utc)
        except (ValueError, OSError):
            # Handle out of range timestamps
            return datetime.now(timezone.utc)
            
    def _custom_parse(
        self,
        timestamp: str,
        timezone_str: Optional[str] = None,
        default_year: Optional[int] = None
    ) -> Optional[datetime]:
        """Custom parsing for non-standard formats"""
        
        # Windows Event Log format: 2024-01-15 15:30:45.123456
        match = re.match(
            r'(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?',
            timestamp
        )
        if match:
            groups = match.groups()
            microseconds = 0
            if groups[6]:
                # Pad or truncate to 6 digits
                us_str = groups[6].ljust(6, '0')[:6]
                microseconds = int(us_str)
                
            dt = datetime(
                int(groups[0]), int(groups[1]), int(groups[2]),
                int(groups[3]), int(groups[4]), int(groups[5]),
                microseconds
            )
            
            if timezone_str:
                dt = self._add_timezone(dt, timezone_str)
                
            return dt
            
        # Syslog format with year: 2024 Jan 15 15:30:45
        match = re.match(
            r'(\d{4})\s+(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})',
            timestamp
        )
        if match:
            groups = match.groups()
            month = self.month_map.get(groups[1].lower(), 1)
            
            dt = datetime(
                int(groups[0]), month, int(groups[2]),
                int(groups[3]), int(groups[4]), int(groups[5])
            )
            
            if timezone_str:
                dt = self._add_timezone(dt, timezone_str)
                
            return dt
            
        # Apache format: [15/Jan/2024:15:30:45 +0000]
        match = re.match(
            r'\[?(\d{1,2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([-+]\d{4})?\]?',
            timestamp
        )
        if match:
            groups = match.groups()
            month = self.month_map.get(groups[1].lower(), 1)
            
            dt = datetime(
                int(groups[2]), month, int(groups[0]),
                int(groups[3]), int(groups[4]), int(groups[5])
            )
            
            # Parse timezone offset
            if groups[6]:
                offset_str = groups[6]
                offset_hours = int(offset_str[1:3])
                offset_minutes = int(offset_str[3:5])
                
                if offset_str[0] == '-':
                    offset = timedelta(hours=-offset_hours, minutes=-offset_minutes)
                else:
                    offset = timedelta(hours=offset_hours, minutes=offset_minutes)
                    
                dt = dt.replace(tzinfo=timezone(offset))
            elif timezone_str:
                dt = self._add_timezone(dt, timezone_str)
                
            return dt
            
        return None
        
    def _add_timezone(self, dt: datetime, timezone_str: str) -> datetime:
        """Add timezone to naive datetime"""
        # Map common abbreviations
        timezone_str = self.tz_map.get(timezone_str.upper(), timezone_str)
        
        try:
            tz = pytz.timezone(timezone_str)
            return tz.localize(dt)
        except:
            # Default to UTC if timezone not found
            return dt.replace(tzinfo=timezone.utc)
            
    def normalize_timestamp(
        self,
        dt: datetime,
        target_tz: Optional[str] = 'UTC'
    ) -> datetime:
        """Normalize timestamp to target timezone"""
        if dt.tzinfo is None:
            # Assume UTC for naive timestamps
            dt = dt.replace(tzinfo=timezone.utc)
            
        if target_tz:
            target_timezone = pytz.timezone(target_tz)
            return dt.astimezone(target_timezone)
            
        return dt
        
    def format_timestamp(
        self,
        dt: datetime,
        format_str: Optional[str] = None
    ) -> str:
        """Format timestamp to string"""
        if format_str:
            return dt.strftime(format_str)
        else:
            # ISO format with timezone
            return dt.isoformat()
            
    def get_time_range(
        self,
        start: Union[str, datetime],
        end: Union[str, datetime]
    ) -> Tuple[datetime, datetime]:
        """Parse and validate time range"""
        # Parse start time
        if isinstance(start, str):
            start_dt = self.parse_timestamp(start)
            if not start_dt:
                raise ValueError(f"Invalid start time: {start}")
        else:
            start_dt = start
            
        # Parse end time
        if isinstance(end, str):
            end_dt = self.parse_timestamp(end)
            if not end_dt:
                raise ValueError(f"Invalid end time: {end}")
        else:
            end_dt = end
            
        # Ensure start is before end
        if start_dt > end_dt:
            start_dt, end_dt = end_dt, start_dt
            
        return start_dt, end_dt
        
    def parse_duration(self, duration_str: str) -> timedelta:
        """Parse duration string to timedelta"""
        # Pattern: 1d2h3m4s or 1 day 2 hours 3 minutes 4 seconds
        pattern = re.compile(
            r'(?:(\d+)\s*d(?:ays?)?)?\s*'
            r'(?:(\d+)\s*h(?:ours?)?)?\s*'
            r'(?:(\d+)\s*m(?:inutes?)?)?\s*'
            r'(?:(\d+)\s*s(?:econds?)?)?',
            re.IGNORECASE
        )
        
        match = pattern.match(duration_str.strip())
        if not match:
            raise ValueError(f"Invalid duration format: {duration_str}")
            
        days = int(match.group(1) or 0)
        hours = int(match.group(2) or 0)
        minutes = int(match.group(3) or 0)
        seconds = int(match.group(4) or 0)
        
        return timedelta(
            days=days,
            hours=hours,
            minutes=minutes,
            seconds=seconds
        )
        
    def format_duration(self, td: timedelta) -> str:
        """Format timedelta to human-readable string"""
        total_seconds = int(td.total_seconds())
        
        days = total_seconds // 86400
        hours = (total_seconds % 86400) // 3600
        minutes = (total_seconds % 3600) // 60
        seconds = total_seconds % 60
        
        parts = []
        if days:
            parts.append(f"{days}d")
        if hours:
            parts.append(f"{hours}h")
        if minutes:
            parts.append(f"{minutes}m")
        if seconds or not parts:
            parts.append(f"{seconds}s")
            
        return ' '.join(parts)
        
    def get_relative_time(self, dt: datetime) -> str:
        """Get human-readable relative time"""
        now = datetime.now(dt.tzinfo or timezone.utc)
        diff = now - dt
        
        if diff.total_seconds() < 0:
            # Future time
            diff = -diff
            prefix = "in "
        else:
            prefix = ""
            
        total_seconds = int(diff.total_seconds())
        
        if total_seconds < 60:
            return f"{prefix}{total_seconds} seconds ago"
        elif total_seconds < 3600:
            minutes = total_seconds // 60
            return f"{prefix}{minutes} minute{'s' if minutes != 1 else ''} ago"
        elif total_seconds < 86400:
            hours = total_seconds // 3600
            return f"{prefix}{hours} hour{'s' if hours != 1 else ''} ago"
        elif total_seconds < 2592000:  # 30 days
            days = total_seconds // 86400
            return f"{prefix}{days} day{'s' if days != 1 else ''} ago"
        else:
            months = total_seconds // 2592000
            return f"{prefix}{months} month{'s' if months != 1 else ''} ago"
            
    def round_timestamp(
        self,
        dt: datetime,
        precision: str = 'second'
    ) -> datetime:
        """Round timestamp to specified precision"""
        if precision == 'second':
            return dt.replace(microsecond=0)
        elif precision == 'minute':
            return dt.replace(second=0, microsecond=0)
        elif precision == 'hour':
            return dt.replace(minute=0, second=0, microsecond=0)
        elif precision == 'day':
            return dt.replace(hour=0, minute=0, second=0, microsecond=0)
        else:
            return dt
            
    def get_time_buckets(
        self,
        start: datetime,
        end: datetime,
        bucket_size: timedelta
    ) -> List[datetime]:
        """Generate time buckets between start and end"""
        buckets = []
        current = start
        
        while current <= end:
            buckets.append(current)
            current += bucket_size
            
        return buckets
        
    def parse_cron_expression(self, cron_expr: str) -> Dict[str, Any]:
        """Parse cron expression"""
        parts = cron_expr.strip().split()
        
        if len(parts) != 5:
            raise ValueError("Invalid cron expression")
            
        return {
            'minute': self._parse_cron_field(parts[0], 0, 59),
            'hour': self._parse_cron_field(parts[1], 0, 23),
            'day': self._parse_cron_field(parts[2], 1, 31),
            'month': self._parse_cron_field(parts[3], 1, 12),
            'weekday': self._parse_cron_field(parts[4], 0, 6)
        }
        
    def _parse_cron_field(
        self,
        field: str,
        min_val: int,
        max_val: int
    ) -> List[int]:
        """Parse individual cron field"""
        if field == '*':
            return list(range(min_val, max_val + 1))
            
        values = []
        
        for part in field.split(','):
            if '-' in part:
                # Range
                start, end = map(int, part.split('-'))
                values.extend(range(start, end + 1))
            elif '/' in part:
                # Step
                range_part, step = part.split('/')
                if range_part == '*':
                    range_vals = range(min_val, max_val + 1)
                else:
                    start, end = map(int, range_part.split('-'))
                    range_vals = range(start, end + 1)
                    
                values.extend(range_vals[::int(step)])
            else:
                # Single value
                values.append(int(part))
                
        return sorted(set(values))
        
    def get_next_cron_time(
        self,
        cron_expr: str,
        after: Optional[datetime] = None
    ) -> datetime:
        """Get next execution time for cron expression"""
        cron = self.parse_cron_expression(cron_expr)
        
        if after is None:
            after = datetime.now()
            
        # Start from next minute
        next_time = after.replace(second=0, microsecond=0) + timedelta(minutes=1)
        
        # Find next matching time
        max_iterations = 366 * 24 * 60  # One year of minutes
        iterations = 0
        
        while iterations < max_iterations:
            if (
                next_time.minute in cron['minute'] and
                next_time.hour in cron['hour'] and
                next_time.day in cron['day'] and
                next_time.month in cron['month'] and
                next_time.weekday() in cron['weekday']
            ):
                return next_time
                
            next_time += timedelta(minutes=1)
            iterations += 1
            
        raise ValueError("Could not find next cron time")


# Utility functions
def parse_timestamp(
    timestamp: Union[str, int, float],
    timezone: Optional[str] = None,
    default_year: Optional[int] = None
) -> Optional[datetime]:
    """Parse timestamp using TimeParser"""
    parser = TimeParser()
    return parser.parse_timestamp(timestamp, timezone, default_year)

def format_timestamp(
    dt: datetime,
    format_str: Optional[str] = None
) -> str:
    """Format timestamp to string"""
    parser = TimeParser()
    return parser.format_timestamp(dt, format_str)

def normalize_to_utc(dt: datetime) -> datetime:
    """Normalize timestamp to UTC"""
    parser = TimeParser()
    return parser.normalize_timestamp(dt, 'UTC')

def get_current_timestamp() -> datetime:
    """Get current UTC timestamp"""
    return datetime.now(timezone.utc)

def timestamp_to_epoch(dt: datetime) -> float:
    """Convert datetime to epoch seconds"""
    return dt.timestamp()

def epoch_to_timestamp(epoch: Union[int, float]) -> datetime:
    """Convert epoch to datetime"""
    parser = TimeParser()
    return parser._parse_epoch(epoch)

def is_recent(
    dt: datetime,
    threshold: timedelta = timedelta(hours=24)
) -> bool:
    """Check if timestamp is recent"""
    now = datetime.now(dt.tzinfo or timezone.utc)
    return now - dt <= threshold

def get_time_ago(dt: datetime) -> str:
    """Get human-readable time ago"""
    parser = TimeParser()
    return parser.get_relative_time(dt)

def parse_duration(duration_str: str) -> timedelta:
    """Parse duration string"""
    parser = TimeParser()
    return parser.parse_duration(duration_str)

def format_duration(td: timedelta) -> str:
    """Format duration to string"""
    parser = TimeParser()
    return parser.format_duration(td)

def get_day_start(dt: datetime) -> datetime:
    """Get start of day"""
    return dt.replace(hour=0, minute=0, second=0, microsecond=0)

def get_day_end(dt: datetime) -> datetime:
    """Get end of day"""
    return dt.replace(hour=23, minute=59, second=59, microsecond=999999)

def get_week_start(dt: datetime) -> datetime:
    """Get start of week (Monday)"""
    days_since_monday = dt.weekday()
    return (dt - timedelta(days=days_since_monday)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )

def get_month_start(dt: datetime) -> datetime:
    """Get start of month"""
    return dt.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

def get_month_end(dt: datetime) -> datetime:
    """Get end of month"""
    last_day = calendar.monthrange(dt.year, dt.month)[1]
    return dt.replace(
        day=last_day,
        hour=23, minute=59, second=59, microsecond=999999
    )

def is_business_hours(
    dt: datetime,
    start_hour: int = 9,
    end_hour: int = 17,
    weekends: bool = False
) -> bool:
    """Check if timestamp is during business hours"""
    # Check weekend
    if not weekends and dt.weekday() >= 5:  # Saturday = 5, Sunday = 6
        return False
        
    # Check hour
    return start_hour <= dt.hour < end_hour

def get_timezone_offset(tz_name: str) -> timedelta:
    """Get timezone offset from UTC"""
    tz = pytz.timezone(tz_name)
    now = datetime.now()
    return tz.utcoffset(now)

def convert_timezone(
    dt: datetime,
    from_tz: str,
    to_tz: str
) -> datetime:
    """Convert between timezones"""
    if dt.tzinfo is None:
        # Assume from_tz for naive datetime
        from_timezone = pytz.timezone(from_tz)
        dt = from_timezone.localize(dt)
    
    to_timezone = pytz.timezone(to_tz)
    return dt.astimezone(to_timezone)