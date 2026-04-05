#!/usr/bin/env python3
"""
DevOps Log Parser
Intelligent log analysis tool for system administrators and DevOps engineers.

Parses, analyzes, and generates insights from various log formats:
- Web servers (nginx, Apache)
- System logs (syslog, journald)
- Docker containers
- Application logs
- Custom formats

Author: lexcellent
License: MIT
"""

import re
import json
import argparse
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
import gzip
import sys


@dataclass
class LogEntry:
    """Represents a parsed log entry."""
    timestamp: Optional[datetime] = None
    level: Optional[str] = None
    message: str = ""
    source: Optional[str] = None
    ip_address: Optional[str] = None
    http_method: Optional[str] = None
    http_path: Optional[str] = None
    http_status: Optional[int] = None
    http_size: Optional[int] = None
    user_agent: Optional[str] = None
    raw_line: str = ""
    line_number: int = 0
    

class LogParser:
    """Main log parser with multi-format support."""
    
    # Log level severity mapping
    SEVERITY = {
        'DEBUG': 0,
        'INFO': 1,
        'NOTICE': 2,
        'WARNING': 3,
        'WARN': 3,
        'ERROR': 4,
        'ERR': 4,
        'CRITICAL': 5,
        'CRIT': 5,
        'ALERT': 6,
        'EMERGENCY': 7,
        'EMERG': 7
    }
    
    # Common log patterns
    PATTERNS = {
        # nginx/Apache combined log format
        'nginx_combined': re.compile(
            r'(?P<ip>[\d.]+) - (?P<user>\S+) \[(?P<timestamp>[^\]]+)\] '
            r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" '
            r'(?P<status>\d+) (?P<size>\d+|-) '
            r'"(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"'
        ),
        
        # nginx error log
        'nginx_error': re.compile(
            r'(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) '
            r'\[(?P<level>\w+)\] (?P<pid>\d+)#(?P<tid>\d+): '
            r'(?P<message>.*)'
        ),
        
        # syslog format
        'syslog': re.compile(
            r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) '
            r'(?P<hostname>\S+) (?P<program>\S+?)(\[(?P<pid>\d+)\])?: '
            r'(?P<message>.*)'
        ),
        
        # Docker container logs (JSON)
        'docker_json': re.compile(
            r'\{.*"log".*"stream".*"time".*\}'
        ),
        
        # Generic timestamp + level + message
        'generic': re.compile(
            r'(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})'
            r'(?:\.\d{3,6})?\s*'
            r'(?P<level>DEBUG|INFO|WARN(?:ING)?|ERROR|CRITICAL|FATAL)?'
            r'\s*[\[\(]?(?P<source>[^\]\)]+)?[\]\)]?'
            r'\s*[:\-]?\s*'
            r'(?P<message>.*)'
        ),
        
        # Python logging format
        'python': re.compile(
            r'(?P<level>DEBUG|INFO|WARNING|ERROR|CRITICAL) '
            r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) '
            r'(?P<module>\S+) (?P<message>.*)'
        )
    }
    
    def __init__(self, log_file: str, format_hint: Optional[str] = None):
        """
        Initialize log parser.
        
        Args:
            log_file: Path to log file (supports .gz)
            format_hint: Optional format hint ('nginx', 'apache', 'syslog', 'docker', 'generic')
        """
        self.log_file = log_file
        self.format_hint = format_hint
        self.entries: List[LogEntry] = []
        self.stats = defaultdict(int)
        self.errors: List[LogEntry] = []
        self.warnings: List[LogEntry] = []
    
    def _open_file(self):
        """Open log file (handles gzip compression)."""
        if self.log_file.endswith('.gz'):
            return gzip.open(self.log_file, 'rt', encoding='utf-8', errors='ignore')
        return open(self.log_file, 'r', encoding='utf-8', errors='ignore')
    
    def _parse_timestamp(self, ts_string: str) -> Optional[datetime]:
        """
        Parse timestamp from various formats.
        
        Args:
            ts_string: Timestamp string
            
        Returns:
            datetime object or None
        """
        formats = [
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%dT%H:%M:%S',
            '%Y/%m/%d %H:%M:%S',
            '%d/%b/%Y:%H:%M:%S',
            '%b %d %H:%M:%S',
            '%Y-%m-%d %H:%M:%S,%f',
        ]
        
        for fmt in formats:
            try:
                dt = datetime.strptime(ts_string.split()[0] + ' ' + ts_string.split()[1] if len(ts_string.split()) > 1 else ts_string, fmt)
                # Add current year for syslog format (which doesn't include year)
                if fmt == '%b %d %H:%M:%S':
                    dt = dt.replace(year=datetime.now().year)
                return dt
            except (ValueError, IndexError):
                continue
        
        return None
    
    def _detect_format(self, line: str) -> Optional[str]:
        """
        Auto-detect log format.
        
        Args:
            line: Sample log line
            
        Returns:
            Format name or None
        """
        if self.format_hint:
            return self.format_hint
        
        # Try each pattern
        for fmt_name, pattern in self.PATTERNS.items():
            if pattern.search(line):
                return fmt_name
        
        return 'generic'
    
    def _parse_line(self, line: str, line_num: int) -> Optional[LogEntry]:
        """
        Parse a single log line.
        
        Args:
            line: Log line to parse
            line_num: Line number in file
            
        Returns:
            LogEntry object or None
        """
        line = line.strip()
        if not line:
            return None
        
        entry = LogEntry(raw_line=line, line_number=line_num)
        
        # Detect format
        fmt = self._detect_format(line)
        
        if fmt == 'nginx_combined':
            match = self.PATTERNS['nginx_combined'].match(line)
            if match:
                d = match.groupdict()
                entry.ip_address = d['ip']
                entry.timestamp = self._parse_timestamp(d['timestamp'])
                entry.http_method = d['method']
                entry.http_path = d['path']
                entry.http_status = int(d['status'])
                entry.http_size = int(d['size']) if d['size'] != '-' else None
                entry.user_agent = d['user_agent']
                entry.message = f"{d['method']} {d['path']} {d['status']}"
                
                # Classify by HTTP status
                if entry.http_status >= 500:
                    entry.level = 'ERROR'
                elif entry.http_status >= 400:
                    entry.level = 'WARNING'
                else:
                    entry.level = 'INFO'
        
        elif fmt == 'nginx_error':
            match = self.PATTERNS['nginx_error'].match(line)
            if match:
                d = match.groupdict()
                entry.timestamp = self._parse_timestamp(d['timestamp'])
                entry.level = d['level'].upper()
                entry.message = d['message']
                entry.source = 'nginx'
        
        elif fmt == 'syslog':
            match = self.PATTERNS['syslog'].match(line)
            if match:
                d = match.groupdict()
                entry.timestamp = self._parse_timestamp(d['timestamp'])
                entry.source = d.get('program', 'unknown')
                entry.message = d['message']
                
                # Try to extract level from message
                if any(word in entry.message.upper() for word in ['ERROR', 'ERR', 'FAIL']):
                    entry.level = 'ERROR'
                elif any(word in entry.message.upper() for word in ['WARN', 'WARNING']):
                    entry.level = 'WARNING'
                else:
                    entry.level = 'INFO'
        
        elif fmt == 'docker_json':
            try:
                data = json.loads(line)
                entry.message = data.get('log', '').strip()
                entry.timestamp = self._parse_timestamp(data.get('time', ''))
                entry.source = 'docker'
                
                # Extract level from log content
                for level in self.SEVERITY.keys():
                    if level in entry.message.upper():
                        entry.level = level
                        break
                
                if not entry.level:
                    entry.level = 'INFO'
            except json.JSONDecodeError:
                pass
        
        elif fmt == 'python':
            match = self.PATTERNS['python'].match(line)
            if match:
                d = match.groupdict()
                entry.level = d['level']
                entry.timestamp = self._parse_timestamp(d['timestamp'])
                entry.source = d.get('module', 'python')
                entry.message = d['message']
        
        else:  # generic
            match = self.PATTERNS['generic'].match(line)
            if match:
                d = match.groupdict()
                entry.timestamp = self._parse_timestamp(d.get('timestamp', ''))
                entry.level = d.get('level', 'INFO')
                entry.source = d.get('source')
                entry.message = d.get('message', line)
            else:
                entry.message = line
                entry.level = 'INFO'
        
        return entry
    
    def parse(self, max_lines: Optional[int] = None) -> List[LogEntry]:
        """
        Parse log file.
        
        Args:
            max_lines: Maximum lines to parse (None = all)
            
        Returns:
            List of LogEntry objects
        """
        print(f"[*] Parsing log file: {self.log_file}")
        
        with self._open_file() as f:
            for line_num, line in enumerate(f, 1):
                if max_lines and line_num > max_lines:
                    break
                
                entry = self._parse_line(line, line_num)
                if entry:
                    self.entries.append(entry)
                    
                    # Update statistics
                    self.stats['total_lines'] += 1
                    if entry.level:
                        self.stats[f'level_{entry.level.lower()}'] += 1
                    
                    # Collect errors and warnings
                    if entry.level and self.SEVERITY.get(entry.level, 0) >= self.SEVERITY['ERROR']:
                        self.errors.append(entry)
                    elif entry.level and self.SEVERITY.get(entry.level, 0) == self.SEVERITY['WARNING']:
                        self.warnings.append(entry)
                    
                    # HTTP status stats
                    if entry.http_status:
                        self.stats[f'http_{entry.http_status // 100}xx'] += 1
        
        print(f"[+] Parsed {len(self.entries)} log entries")
        return self.entries
    
    def analyze(self) -> Dict[str, Any]:
        """
        Perform log analysis.
        
        Returns:
            Analysis results dictionary
        """
        analysis = {
            'summary': dict(self.stats),
            'error_count': len(self.errors),
            'warning_count': len(self.warnings),
            'top_errors': [],
            'top_ips': [],
            'top_paths': [],
            'time_range': {},
            'anomalies': []
        }
        
        # Time range
        timestamps = [e.timestamp for e in self.entries if e.timestamp]
        if timestamps:
            analysis['time_range'] = {
                'start': min(timestamps).isoformat(),
                'end': max(timestamps).isoformat(),
                'duration_hours': (max(timestamps) - min(timestamps)).total_seconds() / 3600
            }
        
        # Top error messages
        error_messages = [e.message for e in self.errors]
        error_counts = Counter(error_messages)
        analysis['top_errors'] = [
            {'message': msg, 'count': count}
            for msg, count in error_counts.most_common(10)
        ]
        
        # Top IP addresses
        ips = [e.ip_address for e in self.entries if e.ip_address]
        ip_counts = Counter(ips)
        analysis['top_ips'] = [
            {'ip': ip, 'requests': count}
            for ip, count in ip_counts.most_common(10)
        ]
        
        # Top paths
        paths = [e.http_path for e in self.entries if e.http_path]
        path_counts = Counter(paths)
        analysis['top_paths'] = [
            {'path': path, 'hits': count}
            for path, count in path_counts.most_common(10)
        ]
        
        # Detect anomalies
        analysis['anomalies'] = self._detect_anomalies()
        
        return analysis
    
    def _detect_anomalies(self) -> List[Dict[str, Any]]:
        """
        Detect anomalies in logs.
        
        Returns:
            List of anomaly descriptions
        """
        anomalies = []
        
        # High error rate
        total = self.stats.get('total_lines', 0)
        errors = len(self.errors)
        if total > 0 and (errors / total) > 0.1:  # >10% errors
            anomalies.append({
                'type': 'high_error_rate',
                'severity': 'high',
                'description': f'High error rate: {errors}/{total} ({errors/total*100:.1f}%)'
            })
        
        # Too many 5xx errors
        http_5xx = self.stats.get('http_5', 0)
        http_total = sum(self.stats.get(f'http_{i}', 0) for i in range(1, 6))
        if http_total > 0 and (http_5xx / http_total) > 0.05:  # >5% 5xx
            anomalies.append({
                'type': 'high_5xx_rate',
                'severity': 'high',
                'description': f'High 5xx error rate: {http_5xx}/{http_total} ({http_5xx/http_total*100:.1f}%)'
            })
        
        # Repeated error patterns
        error_messages = [e.message for e in self.errors]
        error_counts = Counter(error_messages)
        for msg, count in error_counts.most_common(3):
            if count > 10:
                anomalies.append({
                    'type': 'repeated_error',
                    'severity': 'medium',
                    'description': f'Repeated error ({count}x): {msg[:100]}'
                })
        
        # Suspicious IP activity (>1000 requests from single IP)
        ips = [e.ip_address for e in self.entries if e.ip_address]
        ip_counts = Counter(ips)
        for ip, count in ip_counts.most_common(5):
            if count > 1000:
                anomalies.append({
                    'type': 'high_request_ip',
                    'severity': 'medium',
                    'description': f'Suspicious activity from {ip}: {count} requests'
                })
        
        return anomalies
    
    def generate_report(self, format: str = 'text') -> str:
        """
        Generate analysis report.
        
        Args:
            format: Output format ('text' or 'json')
            
        Returns:
            Report as string
        """
        analysis = self.analyze()
        
        if format == 'json':
            return json.dumps(analysis, indent=2)
        
        # Text format
        report = []
        report.append("\n" + "="*70)
        report.append("LOG ANALYSIS REPORT")
        report.append("="*70)
        report.append(f"File: {self.log_file}")
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("="*70 + "\n")
        
        # Summary
        report.append("SUMMARY:")
        report.append(f"  Total Lines: {analysis['summary'].get('total_lines', 0):,}")
        report.append(f"  Errors: {analysis['error_count']:,}")
        report.append(f"  Warnings: {analysis['warning_count']:,}")
        
        # Time range
        if analysis['time_range']:
            report.append(f"\nTIME RANGE:")
            report.append(f"  Start: {analysis['time_range']['start']}")
            report.append(f"  End: {analysis['time_range']['end']}")
            report.append(f"  Duration: {analysis['time_range']['duration_hours']:.2f} hours")
        
        # Log levels
        report.append(f"\nLOG LEVELS:")
        for level in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
            count = analysis['summary'].get(f'level_{level.lower()}', 0)
            if count > 0:
                report.append(f"  {level}: {count:,}")
        
        # HTTP status codes
        http_stats = {k: v for k, v in analysis['summary'].items() if k.startswith('http_')}
        if http_stats:
            report.append(f"\nHTTP STATUS CODES:")
            for status, count in sorted(http_stats.items()):
                report.append(f"  {status.upper()}: {count:,}")
        
        # Top errors
        if analysis['top_errors']:
            report.append(f"\nTOP ERRORS:")
            for idx, err in enumerate(analysis['top_errors'][:5], 1):
                report.append(f"  {idx}. [{err['count']}x] {err['message'][:80]}")
        
        # Top IPs
        if analysis['top_ips']:
            report.append(f"\nTOP IP ADDRESSES:")
            for idx, ip_data in enumerate(analysis['top_ips'][:5], 1):
                report.append(f"  {idx}. {ip_data['ip']}: {ip_data['requests']:,} requests")
        
        # Top paths
        if analysis['top_paths']:
            report.append(f"\nTOP PATHS:")
            for idx, path_data in enumerate(analysis['top_paths'][:5], 1):
                report.append(f"  {idx}. {path_data['path']}: {path_data['hits']:,} hits")
        
        # Anomalies
        if analysis['anomalies']:
            report.append(f"\n⚠️  ANOMALIES DETECTED:")
            for anomaly in analysis['anomalies']:
                severity_icon = {'high': '🔴', 'medium': '🟡', 'low': '🟢'}.get(anomaly['severity'], '⚪')
                report.append(f"  {severity_icon} [{anomaly['severity'].upper()}] {anomaly['description']}")
        
        report.append("\n" + "="*70)
        
        return "\n".join(report)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="DevOps Log Parser - Intelligent log analysis tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "logfile",
        help="Path to log file (supports .gz compression)"
    )
    parser.add_argument(
        "--format",
        choices=['nginx', 'apache', 'syslog', 'docker', 'python', 'generic'],
        help="Log format hint (auto-detected if not specified)"
    )
    parser.add_argument(
        "--output-format",
        choices=['text', 'json'],
        default='text',
        help="Report output format (default: text)"
    )
    parser.add_argument(
        "--output", "-o",
        help="Save report to file"
    )
    parser.add_argument(
        "--max-lines",
        type=int,
        help="Maximum lines to parse (default: all)"
    )
    parser.add_argument(
        "--errors-only",
        action='store_true',
        help="Show only errors and warnings"
    )
    
    args = parser.parse_args()
    
    try:
        # Parse logs
        log_parser = LogParser(args.logfile, format_hint=args.format)
        log_parser.parse(max_lines=args.max_lines)
        
        # Generate report
        if args.errors_only:
            print(f"\n{'='*70}")
            print("ERRORS AND WARNINGS")
            print(f"{'='*70}\n")
            
            if log_parser.errors:
                print(f"ERRORS ({len(log_parser.errors)}):")
                for entry in log_parser.errors[:20]:  # Show first 20
                    ts = entry.timestamp.strftime('%Y-%m-%d %H:%M:%S') if entry.timestamp else 'N/A'
                    print(f"  [{ts}] {entry.message}")
            
            if log_parser.warnings:
                print(f"\nWARNINGS ({len(log_parser.warnings)}):")
                for entry in log_parser.warnings[:20]:  # Show first 20
                    ts = entry.timestamp.strftime('%Y-%m-%d %H:%M:%S') if entry.timestamp else 'N/A'
                    print(f"  [{ts}] {entry.message}")
        else:
            report = log_parser.generate_report(format=args.output_format)
            
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(report)
                print(f"[+] Report saved to: {args.output}")
            else:
                print(report)
        
    except FileNotFoundError:
        print(f"[!] Error: File not found: {args.logfile}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
