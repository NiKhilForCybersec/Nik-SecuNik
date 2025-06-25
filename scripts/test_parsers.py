#!/usr/bin/env python3
"""
Test utility for SecuNik LogX parsers
"""

import sys
import os
import json
import time
import argparse
from pathlib import Path
from typing import Dict, List, Optional
import traceback
from tabulate import tabulate

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from core.parser_factory import ParserFactory
from core.file_identifier import FileIdentifier
from utils.file_utils import calculate_file_hash

class ParserTester:
    def __init__(self, test_dir: str = "tests/test_files"):
        self.test_dir = Path(test_dir)
        self.parser_factory = ParserFactory()
        self.file_identifier = FileIdentifier()
        self.results = []
        
    def create_test_files(self):
        """Create sample test files"""
        self.test_dir.mkdir(parents=True, exist_ok=True)
        
        # Syslog
        (self.test_dir / "syslog.log").write_text(
            "Jan 1 12:00:00 server sshd[1234]: Accepted password for user from 192.168.1.100 port 22 ssh2\n"
            "Jan 1 12:00:01 server kernel: [UFW BLOCK] IN=eth0 OUT= SRC=10.0.0.1 DST=192.168.1.1\n"
        )
        
        # Windows Event Log (simplified XML)
        (self.test_dir / "windows.xml").write_text(
            '<?xml version="1.0"?>\n'
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n'
            '  <System>\n'
            '    <EventID>4624</EventID>\n'
            '    <TimeCreated SystemTime="2024-01-01T12:00:00.000Z"/>\n'
            '  </System>\n'
            '</Event>\n'
        )
        
        # Apache Log
        (self.test_dir / "apache.log").write_text(
            '192.168.1.100 - - [01/Jan/2024:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234\n'
            '192.168.1.101 - - [01/Jan/2024:12:00:01 +0000] "POST /api/login HTTP/1.1" 401 567\n'
        )
        
        # JSON Log
        (self.test_dir / "app.json").write_text(
            '{"timestamp": "2024-01-01T12:00:00Z", "level": "ERROR", "message": "Database connection failed"}\n'
            '{"timestamp": "2024-01-01T12:00:01Z", "level": "INFO", "message": "Service started"}\n'
        )
        
        # CSV Data
        (self.test_dir / "data.csv").write_text(
            "timestamp,source_ip,destination_ip,action\n"
            "2024-01-01 12:00:00,192.168.1.100,10.0.0.1,ALLOW\n"
            "2024-01-01 12:00:01,192.168.1.101,10.0.0.2,BLOCK\n"
        )
        
        # Email (EML)
        (self.test_dir / "email.eml").write_text(
            "From: sender@example.com\n"
            "To: recipient@example.com\n"
            "Subject: Test Email\n"
            "Date: Mon, 1 Jan 2024 12:00:00 +0000\n"
            "\n"
            "This is a test email.\n"
        )
        
        print(f"Created test files in {self.test_dir}")
        
    def test_file(self, filepath: Path) -> Dict:
        """Test a single file"""
        result = {
            "file": filepath.name,
            "size": filepath.stat().st_size,
            "identified_type": None,
            "parser": None,
            "success": False,
            "entries_parsed": 0,
            "parse_time": 0,
            "error": None
        }
        
        try:
            # Identify file type
            file_info = self.file_identifier.identify(str(filepath))
            result["identified_type"] = file_info.get("type", "unknown")
            
            # Get parser
            parser = self.parser_factory.get_parser(file_info)
            if not parser:
                result["error"] = "No parser available"
                return result
                
            result["parser"] = parser.__class__.__name__
            
            # Parse file
            start_time = time.time()
            parsed_data = parser.parse(str(filepath))
            result["parse_time"] = round(time.time() - start_time, 3)
            
            # Count entries
            if isinstance(parsed_data, dict):
                if "entries" in parsed_data:
                    result["entries_parsed"] = len(parsed_data["entries"])
                elif "events" in parsed_data:
                    result["entries_parsed"] = len(parsed_data["events"])
                else:
                    result["entries_parsed"] = 1
            elif isinstance(parsed_data, list):
                result["entries_parsed"] = len(parsed_data)
            else:
                result["entries_parsed"] = 1
                
            result["success"] = True
            
        except Exception as e:
            result["error"] = str(e)
            if args.verbose:
                traceback.print_exc()
                
        return result
        
    def test_all_files(self, pattern: str = "*"):
        """Test all files matching pattern"""
        files = list(self.test_dir.glob(pattern))
        
        if not files:
            print(f"No files found matching pattern: {pattern}")
            return
            
        print(f"\nTesting {len(files)} files...\n")
        
        for filepath in files:
            if filepath.is_file():
                result = self.test_file(filepath)
                self.results.append(result)
                
                # Print progress
                status = "✓" if result["success"] else "✗"
                print(f"{status} {result['file']:<30} {result['parser']:<20} "
                      f"{result['entries_parsed']:>5} entries in {result['parse_time']:.3f}s")
                
                if result["error"] and args.verbose:
                    print(f"  Error: {result['error']}")
                    
    def print_summary(self):
        """Print test summary"""
        if not self.results:
            return
            
        print("\n" + "="*80)
        print("PARSER TEST SUMMARY")
        print("="*80)
        
        # Summary table
        headers = ["File", "Type", "Parser", "Success", "Entries", "Time (s)"]
        rows = []
        
        for r in self.results:
            rows.append([
                r["file"],
                r["identified_type"],
                r["parser"] or "N/A",
                "✓" if r["success"] else "✗",
                r["entries_parsed"],
                r["parse_time"]
            ])
            
        print(tabulate(rows, headers=headers, tablefmt="grid"))
        
        # Statistics
        total = len(self.results)
        successful = sum(1 for r in self.results if r["success"])
        failed = total - successful
        total_time = sum(r["parse_time"] for r in self.results)
        total_entries = sum(r["entries_parsed"] for r in self.results)
        
        print(f"\nTotal files tested: {total}")
        print(f"Successful: {successful} ({successful/total*100:.1f}%)")
        print(f"Failed: {failed} ({failed/total*100:.1f}%)")
        print(f"Total entries parsed: {total_entries}")
        print(f"Total parse time: {total_time:.3f}s")
        
        if failed > 0:
            print("\nFailed files:")
            for r in self.results:
                if not r["success"]:
                    print(f"  - {r['file']}: {r['error']}")
                    
    def test_parser_performance(self, parser_name: str, test_file: str, iterations: int = 10):
        """Test parser performance"""
        filepath = Path(test_file)
        if not filepath.exists():
            print(f"Test file not found: {test_file}")
            return
            
        print(f"\nPerformance testing {parser_name} with {filepath.name} ({iterations} iterations)...")
        
        times = []
        for i in range(iterations):
            result = self.test_file(filepath)
            if result["success"]:
                times.append(result["parse_time"])
            else:
                print(f"Parse failed: {result['error']}")
                return
                
        avg_time = sum(times) / len(times)
        min_time = min(times)
        max_time = max(times)
        
        print(f"\nPerformance Results:")
        print(f"  Average: {avg_time:.3f}s")
        print(f"  Min: {min_time:.3f}s")
        print(f"  Max: {max_time:.3f}s")
        print(f"  Throughput: {filepath.stat().st_size / avg_time / 1024 / 1024:.2f} MB/s")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test SecuNik LogX parsers")
    parser.add_argument("--create", action="store_true", help="Create test files")
    parser.add_argument("--pattern", default="*", help="File pattern to test")
    parser.add_argument("--file", help="Test specific file")
    parser.add_argument("--parser", help="Test specific parser")
    parser.add_argument("--performance", action="store_true", help="Run performance test")
    parser.add_argument("--iterations", type=int, default=10, help="Performance test iterations")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    tester = ParserTester()
    
    if args.create:
        tester.create_test_files()
    elif args.performance and args.parser and args.file:
        tester.test_parser_performance(args.parser, args.file, args.iterations)
    elif args.file:
        result = tester.test_file(Path(args.file))
        tester.results = [result]
        tester.print_summary()
    else:
        tester.test_all_files(args.pattern)
        tester.print_summary()