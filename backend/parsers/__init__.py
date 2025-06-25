"""
Parsers Package
Auto-imports all parser classes for easy discovery
"""

# Import all parser classes
from parsers.base_parser import BaseParser, ParsedEntry, ParseResult

# Import specific parsers
from parsers.logs.syslog_parser import SyslogParser
from parsers.logs.windows_event_parser import WindowsEventParser
from parsers.network.pcap_parser import PcapParser
from parsers.structured.json_parser import JsonParser
from parsers.structured.csv_parser import CsvParser
from parsers.archives.zip_parser import ZipParser
from parsers.generic.text_parser import TextParser

# Export all parser classes
__all__ = [
    'BaseParser',
    'ParsedEntry',
    'ParseResult',
    'SyslogParser',
    'WindowsEventParser', 
    'PcapParser',
    'JsonParser',
    'CsvParser',
    'ZipParser',
    'TextParser'
]

# Parser registry for easy lookup
PARSER_REGISTRY = {
    'syslog': SyslogParser,
    'windows_event': WindowsEventParser,
    'pcap': PcapParser,
    'json': JsonParser,
    'csv': CsvParser,
    'zip': ZipParser,
    'text': TextParser
}