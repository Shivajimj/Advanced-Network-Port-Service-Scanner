# Advanced Network Port & Service Scanner

A Python-based multithreaded TCP port scanner designed for cybersecurity learning and authorized network security testing.

## Features

- TCP port scanning
- Multithreaded scanning
- Multiple IPv4 target support
- Service identification
- Banner grabbing
- HTTP response detection
- Live progress bar
- Scan speed and ETA calculation
- Open, closed and error statistics
- JSON report generation
- CSV report generation
- Separate error reports
- Timestamped activity logging
- Input validation
- Exception handling
- Keyboard interruption handling

## Technologies Used

- Python 3
- Kali Linux
- Socket Programming
- ThreadPoolExecutor
- Argparse
- JSON
- CSV
- Logging

## Project Structure

    Advanced-Network-Port-Service-Scanner/
    ├── scanner.py
    ├── README.md
    ├── requirements.txt
    ├── .gitignore
    ├── reports/
    └── logs/

## Installation

Clone the repository:

    git clone YOUR_REPOSITORY_URL

Enter the project directory:

    cd Advanced-Network-Port-Service-Scanner

Check Python:

    python3 --version

No external Python packages are currently required.

## Usage

Display help:

    python3 scanner.py --help

Scan one target and port:

    python3 scanner.py -t 127.0.0.1 -p 8080

Scan a port range:

    python3 scanner.py -t 127.0.0.1 -p 1-1000

Scan multiple targets:

    python3 scanner.py --targets 127.0.0.1,192.168.1.1 -p 80

Customize threads and timeout:

    python3 scanner.py -t 127.0.0.1 -p 1-1000 -T 100 --timeout 1

## Reports

The scanner generates:

- JSON scan reports
- CSV scan reports
- Error CSV reports

Reports are stored in the reports/ directory.

Activity logs are stored in:

    logs/scanner.log

## Learning Objectives

This project demonstrates practical knowledge of:

- TCP/IP networking
- Python socket programming
- Multithreading
- Network service identification
- Banner grabbing
- Exception handling
- Report generation
- Cybersecurity automation

## Disclaimer

This project is intended for educational purposes and authorized security testing only.

Only scan systems and networks for which you have explicit permission.

## Author

Cybersecurity Portfolio Project

Developed using Python 3 on Kali Linux.
