# Windows System Security Auditor

A Python-based command-line tool to scan Windows systems for security misconfigurations and vulnerabilities. This tool helps system administrators and security professionals identify potential security issues on Windows machines.

## Features

- Basic and comprehensive security scans
- Detailed reporting in text or JSON format
- Output to console or file
- Windows-specific security checks including:
  - System information gathering
  - Windows Update status
  - Firewall configuration
  - Autorun programs
  - User accounts
  - Running services

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

Additional options:
- `--scan basic|full`: Specify the type of scan to perform
- `--output FILE`: Save results to a file
- `--format text|json`: Choose output format

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## License

MIT License - see the LICENSE file for details