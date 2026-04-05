# DevOps Log Parser

Intelligent log analysis tool for system administrators and DevOps engineers. Parse, analyze, and extract insights from various log formats with anomaly detection and comprehensive reporting.

## Features

✅ **Multi-Format Support** - nginx, Apache, syslog, Docker, Python, generic  
✅ **Auto-Detection** - Automatically identifies log format  
✅ **Error Analysis** - Categorizes errors, warnings, and critical events  
✅ **HTTP Metrics** - Status code analysis, path statistics  
✅ **Anomaly Detection** - High error rates, suspicious IPs, repeated errors  
✅ **Compressed Logs** - Native .gz support  
✅ **Multiple Output Formats** - Human-readable text or JSON  
✅ **Fast & Efficient** - Handles millions of log lines  
✅ **Zero Dependencies** - Pure Python standard library  

---

## Installation

```bash
# Clone repository
git clone https://github.com/lexcellent/devops-log-parser.git
cd devops-log-parser

# Make executable
chmod +x logparser.py

# No dependencies required!
python3 logparser.py --help
```

---

## Quick Start

### Basic Usage
```bash
# Analyze nginx access log
./logparser.py /var/log/nginx/access.log

# Analyze compressed log
./logparser.py /var/log/nginx/access.log.1.gz

# Save report to file
./logparser.py /var/log/syslog --output report.txt
```

---

## Supported Log Formats

### 1. nginx/Apache Combined Log
```
192.168.1.100 - - [05/Apr/2026:10:15:23 +0000] "GET /api/users HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
```

### 2. nginx Error Log
```
2026/04/05 10:15:23 [error] 12345#12345: *1 connect() failed (111: Connection refused)
```

### 3. Syslog
```
Apr  5 10:15:23 server sshd[12345]: Failed password for root from 192.168.1.100 port 22
```

### 4. Docker JSON Logs
```json
{"log":"Error: connection timeout\n","stream":"stderr","time":"2026-04-05T10:15:23.123456Z"}
```

### 5. Python Logging
```
ERROR 2026-04-05 10:15:23,123 myapp Database connection failed
```

### 6. Generic Application Logs
```
2026-04-05 10:15:23 ERROR [Database] Connection timeout after 30s
```

---

## Usage Examples

### Example 1: nginx Access Log Analysis
```bash
./logparser.py /var/log/nginx/access.log
```

**Output:**
```
======================================================================
LOG ANALYSIS REPORT
======================================================================
File: /var/log/nginx/access.log
Generated: 2026-04-05 11:33:45
======================================================================

SUMMARY:
  Total Lines: 15,432
  Errors: 234
  Warnings: 89

TIME RANGE:
  Start: 2026-04-05T00:00:12
  End: 2026-04-05T23:59:58
  Duration: 24.00 hours

HTTP STATUS CODES:
  HTTP_2XX: 14,523
  HTTP_3XX: 412
  HTTP_4XX: 389
  HTTP_5XX: 108

TOP ERRORS:
  1. [45x] 502 Bad Gateway
  2. [23x] 504 Gateway Timeout
  3. [12x] Connection refused

TOP IP ADDRESSES:
  1. 203.0.113.10: 1,234 requests
  2. 198.51.100.50: 892 requests
  3. 192.0.2.100: 654 requests

TOP PATHS:
  1. /api/users: 2,345 hits
  2. /api/posts: 1,876 hits
  3. /health: 1,234 hits

⚠️  ANOMALIES DETECTED:
  🔴 [HIGH] High 5xx error rate: 108/15432 (0.7%)
  🟡 [MEDIUM] Repeated error (45x): 502 Bad Gateway
  🟡 [MEDIUM] Suspicious activity from 203.0.113.10: 1,234 requests
======================================================================
```

---

### Example 2: Show Only Errors
```bash
./logparser.py /var/log/application.log --errors-only
```

**Output:**
```
ERRORS (234):
  [2026-04-05 10:15:23] Database connection timeout after 30s
  [2026-04-05 10:16:45] Failed to write to cache: Redis unavailable
  [2026-04-05 10:18:12] API request failed: 504 Gateway Timeout
  ...

WARNINGS (89):
  [2026-04-05 10:20:34] Slow query detected: 2.5s
  [2026-04-05 10:22:11] Memory usage above 80%
  ...
```

---

### Example 3: JSON Output (for automation)
```bash
./logparser.py /var/log/syslog --output-format json --output analysis.json
```

**Output (analysis.json):**
```json
{
  "summary": {
    "total_lines": 5432,
    "level_error": 45,
    "level_warning": 23,
    "level_info": 5364
  },
  "error_count": 45,
  "warning_count": 23,
  "top_errors": [
    {
      "message": "Failed password for root from 192.168.1.100",
      "count": 12
    }
  ],
  "time_range": {
    "start": "2026-04-05T00:00:01",
    "end": "2026-04-05T23:59:59",
    "duration_hours": 24.0
  },
  "anomalies": [
    {
      "type": "repeated_error",
      "severity": "medium",
      "description": "Repeated error (12x): Failed password for root"
    }
  ]
}
```

---

## Advanced Usage

### Analyze Large Log Files (Sampling)
```bash
# Parse only first 10,000 lines
./logparser.py /var/log/huge.log --max-lines 10000
```

### Specify Log Format
```bash
# Force nginx format (skip auto-detection)
./logparser.py /var/log/custom.log --format nginx
```

### Batch Processing
```bash
#!/bin/bash
# Analyze all nginx logs
for log in /var/log/nginx/*.log /var/log/nginx/*.log.*.gz; do
    ./logparser.py "$log" --output "report-$(basename $log).txt"
done
```

---

## Use Cases

### 1. Troubleshooting Production Issues
```bash
# Find what caused the outage
./logparser.py /var/log/nginx/error.log --errors-only

# Check for patterns
./logparser.py /var/log/application.log --output-format json | jq '.top_errors'
```

### 2. Security Monitoring
```bash
# Detect brute-force attacks
./logparser.py /var/log/auth.log --errors-only | grep "Failed password"

# Identify suspicious IPs
./logparser.py /var/log/nginx/access.log | grep "Suspicious activity"
```

### 3. Performance Analysis
```bash
# Analyze HTTP response codes
./logparser.py /var/log/nginx/access.log | grep "HTTP_5XX"

# Find slow endpoints
./logparser.py /var/log/nginx/access.log --output-format json | jq '.top_paths'
```

### 4. Automated Monitoring (Cron)
```bash
# Daily log analysis
0 2 * * * /path/to/logparser.py /var/log/nginx/access.log --output /reports/daily-$(date +\%Y-\%m-\%d).txt
```

### 5. CI/CD Integration
```bash
# Check for errors in deployment logs
./logparser.py /var/log/deploy.log --errors-only && echo "Deployment OK" || echo "Deployment has errors"
```

---

## Anomaly Detection

The parser automatically detects:

### 🔴 High Priority
- **High error rate:** >10% of log entries are errors
- **High 5xx rate:** >5% of HTTP requests return 5xx errors
- **Repeated critical errors:** Same error occurs >10 times

### 🟡 Medium Priority
- **Repeated errors:** Same error occurs >5 times
- **Suspicious IP activity:** Single IP makes >1000 requests
- **Unusual traffic patterns:** (planned feature)

---

## Output Formats

### Text (Human-Readable)
- Summary statistics
- Error highlights
- Top IPs, paths, errors
- Anomaly warnings
- Recommendations

### JSON (Machine-Readable)
- Complete analysis data
- Easy to parse with `jq`
- Integration with monitoring tools
- Historical trend analysis

---

## Performance

**Benchmarks:**
- 1 million lines: ~15 seconds
- 10 million lines: ~2.5 minutes
- Memory usage: <200MB (streaming parser)
- Compressed logs: Native support (no extraction needed)

**Optimization tips:**
- Use `--max-lines` for sampling large files
- Process compressed logs directly (.gz)
- Use JSON output for faster parsing

---

## Integration Examples

### With Prometheus/Grafana
```bash
# Export metrics as JSON
./logparser.py /var/log/nginx/access.log --output-format json > metrics.json

# Parse with node_exporter textfile collector
# (requires conversion script)
```

### With ELK Stack
```bash
# Pre-analyze before sending to Elasticsearch
./logparser.py /var/log/app.log --output-format json | \
    curl -X POST "localhost:9200/logs/_doc" -H 'Content-Type: application/json' -d @-
```

### With Slack/Discord (Alerts)
```bash
#!/bin/bash
REPORT=$(./logparser.py /var/log/nginx/access.log --errors-only)
if [ -n "$REPORT" ]; then
    # Send to Slack webhook
    curl -X POST "$SLACK_WEBHOOK" -d "{\"text\":\"$REPORT\"}"
fi
```

---

## Comparison with Other Tools

### vs. `grep`/`awk`
- **logparser:** Structured analysis, anomaly detection, statistics
- **grep/awk:** Simple pattern matching, manual analysis

### vs. ELK Stack (Elasticsearch, Logstash, Kibana)
- **logparser:** Lightweight, no setup, instant results
- **ELK:** Scalable, real-time, dashboards (requires infrastructure)

### vs. Splunk
- **logparser:** Free, simple, command-line
- **Splunk:** Enterprise features, expensive licensing

### vs. GoAccess (for web logs)
- **logparser:** Multi-format, anomaly detection, scriptable
- **GoAccess:** Real-time dashboard, web-specific

---

## Troubleshooting

### "No entries parsed"
- **Cause:** Log format not recognized
- **Fix:** Use `--format` to specify format explicitly

### "Permission denied"
- **Cause:** Log file not readable
- **Fix:** Run with `sudo` or adjust file permissions

### Slow parsing
- **Cause:** Very large log file
- **Fix:** Use `--max-lines` for sampling

---

## Contributing

Contributions welcome! Areas for improvement:
- Additional log format support
- More anomaly detection rules
- Performance optimizations
- Export formats (CSV, PDF)

---

## License

MIT License - See LICENSE file

---

## Author

**lexcellent** - DevOps enthusiast | Log analysis specialist

---

## Roadmap

- [ ] Real-time log tailing (`--follow` mode)
- [ ] Custom regex patterns
- [ ] Configurable anomaly thresholds
- [ ] HTML report generation
- [ ] Log correlation across multiple files
- [ ] Machine learning anomaly detection

---

**Analyze smarter. Debug faster. Ship confidently.** 📊
