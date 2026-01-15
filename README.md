# Windows System Security Auditor

A Python-based command-line tool to scan Windows systems for security misconfigurations and vulnerabilities.

## Features

- Basic and full security scans
- Detailed reporting in text or JSON format
- Output to console or file
- Windows-specific security checks

## Installation

1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Run the auditor: `python security_auditor.py`

## Usage

Basic scan:
```
python security_auditor.py --scan basic
```

Full scan with JSON output to file:
```
python security_auditor.py --scan full --format json --output results.json
```

## License

MIT