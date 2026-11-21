
import socket
import json
import csv
import os
import ipaddress
import argparse
import time
import logging
import errno
import sys

from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


# ==================================================
# PROJECT CONFIGURATION
# ==================================================

PROJECT_NAME = "Advanced Network Port & Service Scanner"

REPORT_DIR = "reports"

MAX_ALLOWED_THREADS = 500
MAX_TARGETS = 20

os.makedirs(REPORT_DIR, exist_ok=True)
# ==================================================
# LOGGING CONFIGURATION
# ==================================================

LOG_DIR = "logs"

os.makedirs(LOG_DIR, exist_ok=True)

LOG_FILE = os.path.join(LOG_DIR, "scanner.log")

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

logger = logging.getLogger("NetworkScanner")


# ==================================================
# ERROR CLASSIFICATION
# ==================================================

def classify_connection_error(error_code):

    error_messages = {
        errno.ECONNREFUSED: "Connection refused",
        errno.ETIMEDOUT: "Connection timed out",
        errno.EHOSTUNREACH: "Host unreachable",
        errno.ENETUNREACH: "Network unreachable",
        errno.EACCES: "Permission denied",
        errno.EADDRNOTAVAIL: "Address not available"
    }

    return error_messages.get(
        error_code,
        f"Socket error: {errno.errorcode.get(error_code, error_code)}"
    )


# ==================================================
# REGISTERED SERVICE DETECTION
# ==================================================

def get_registered_service(port):

    try:
        return socket.getservbyport(port, "tcp")

    except OSError:
        return "Unknown"


# ==================================================
# SERVICE FINGERPRINTING
# ==================================================

def identify_service(port, banner):

    lower_banner = banner.lower()

    if lower_banner.startswith("http/"):
        return "HTTP"

    if lower_banner.startswith("ssh-"):
        return "SSH"

    if port == 21 and lower_banner.startswith("220"):
        return "FTP"

    if port in (25, 465, 587) and lower_banner.startswith("220"):
        return "SMTP"

    if port == 3306 and banner != "Not available":
        return "MySQL (possible handshake)"

    if port == 6379 and banner.startswith(("+", "-", "$")):
        return "Redis (possible RESP)"

    return get_registered_service(port)


# ==================================================
# PORT SCANNER
# ==================================================

def scan_port(target, port, timeout):

    banner = "Not available"

    try:

        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        ) as sock:

            sock.settimeout(timeout)

            result = sock.connect_ex((target, port))

            if result != 0:

                if result == errno.ECONNREFUSED:
                    return None

                return {
                    "status": "error",
                    "target": target,
                    "port": port,
                    "error": classify_connection_error(result)
                }

            # HTTP detection

            if port in [80, 8000, 8080, 8888, 3000, 5000]:

                try:

                    sock.sendall(
                        b"HEAD / HTTP/1.0\r\n"
                        b"Host: localhost\r\n"
                        b"Connection: close\r\n\r\n"
                    )

                    response = sock.recv(1024)

                    if response:

                        banner = response.decode(
                            "utf-8",
                            errors="replace"
                        ).splitlines()[0]

                except socket.timeout:
                    banner = "HTTP response timeout"

                except OSError:
                    banner = "HTTP response unavailable"

            else:

                try:

                    response = sock.recv(1024)

                    if response:

                        banner = response.decode(
                            "utf-8",
                            errors="replace"
                        ).strip()

                except socket.timeout:
                    banner = "Banner timeout"

                except OSError:
                    banner = "Banner unavailable"

            detected_service = identify_service(
                port,
                banner
            )

            registered_service = get_registered_service(port)

            return {
                "status": "open",
                "target": target,
                "port": port,
                "protocol": "TCP",
                "state": "OPEN",
                "service": detected_service,
                "registered_service": registered_service,
                "banner": banner[:200]
            }

    except socket.timeout:

        return {
            "status": "error",
            "target": target,
            "port": port,
            "error": "Connection timed out"
        }

    except OSError as error:

        error_code = error.errno

        message = (
            classify_connection_error(error_code)
            if error_code is not None
            else str(error)
        )

        return {
            "status": "error",
            "target": target,
            "port": port,
            "error": message
        }

    except Exception as error:

        return {
            "status": "error",
            "target": target,
            "port": port,
            "error": str(error)
        }


# ==================================================
# PORT RANGE VALIDATION
# ==================================================

def parse_port_range(port_range):

    try:

        if "-" in port_range:

            start, end = map(
                int,
                port_range.split("-", 1)
            )

        else:

            start = end = int(port_range)

        if not (1 <= start <= end <= 65535):
            raise ValueError

        return start, end

    except ValueError:

        raise argparse.ArgumentTypeError(
            "Use a valid range, such as 1-1000 or 8080"
        )


# ==================================================
# LIVE PROGRESS DISPLAY
# ==================================================

def display_progress(
    completed,
    total,
    open_count,
    error_count,
    start_time
):

    elapsed = time.perf_counter() - start_time

    percentage = (
        completed / total * 100
        if total else 100
    )

    speed = (
        completed / elapsed
        if elapsed > 0 else 0
    )

    remaining = (
        (total - completed) / speed
        if speed > 0 else 0
    )

    bar_length = 30

    filled = int(
        bar_length * completed / total
    ) if total else bar_length

    bar = "#" * filled + "-" * (bar_length - filled)

    closed_count = completed - open_count - error_count

    output = (
        f"\r[{bar}] {percentage:6.2f}% "
        f"| Scanned: {completed}/{total} "
        f"| Open: {open_count} "
        f"| Closed: {closed_count} "
        f"| Errors: {error_count} "
        f"| Speed: {speed:.1f}/sec "
        f"| ETA: {remaining:.1f}s"
    )

    sys.stdout.write(output)
    sys.stdout.flush()

    if completed >= total:
        print()


# ==================================================
# REPORT FILENAME
# ==================================================

def generate_report_filename(extension, timestamp):

    return os.path.join(
        REPORT_DIR,
        f"scan_report_{timestamp}.{extension}"
    )


# ==================================================
# JSON REPORT
# ==================================================

def save_json_report(
    results,
    errors,
    targets,
    scan_started,
    scan_completed,
    timestamp,
    total_scans,
    duration,
    interrupted
):

    report = {

        "project": PROJECT_NAME,
        "targets": targets,
        "total_targets": len(targets),
        "total_ports_scanned": total_scans,
        "total_open_ports": len(results),
        "total_errors": len(errors),
        "interrupted": interrupted,
        "scan_started": scan_started,
        "scan_completed": scan_completed,
        "duration_seconds": duration,
        "results": results,
        "errors": errors

    }

    filename = generate_report_filename(
        "json",
        timestamp
    )

    with open(filename, "w") as file:

        json.dump(
            report,
            file,
            indent=4
        )

    print("[+] JSON Report Saved:", filename)


# ==================================================
# CSV REPORT
# ==================================================

def save_csv_report(results, timestamp):

    filename = generate_report_filename(
        "csv",
        timestamp
    )

    fields = [
        "status",
        "target",
        "port",
        "protocol",
        "state",
        "service",
        "registered_service",
        "banner"
    ]

    with open(
        filename,
        "w",
        newline=""
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fields
        )

        writer.writeheader()
        writer.writerows(results)

    print("[+] CSV Report Saved:", filename)


# ==================================================
# ERROR CSV REPORT
# ==================================================

def save_error_report(errors, timestamp):

    filename = generate_report_filename(
        "errors.csv",
        timestamp
    )

    fields = [
        "target",
        "port",
        "error"
    ]

    with open(
        filename,
        "w",
        newline=""
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fields
        )

        writer.writeheader()
        writer.writerows(errors)

    print("[+] Error Report Saved:", filename)


# ==================================================
# MAIN FUNCTION
# ==================================================

def main():

    parser = argparse.ArgumentParser(
        description=PROJECT_NAME
    )

    target_group = parser.add_mutually_exclusive_group(
        required=True
    )

    target_group.add_argument(
        "-t",
        "--target",
        help="Single IPv4 target"
    )

    target_group.add_argument(
        "--targets",
        help="Comma-separated IPv4 targets"
    )

    parser.add_argument(
        "-p",
        "--ports",
        type=parse_port_range,
        default=(1, 1024),
        help="Port range, for example 1-1000"
    )

    parser.add_argument(
        "-T",
        "--threads",
        type=int,
        default=100,
        help="Number of scanning threads"
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout"
    )

    args = parser.parse_args()

    # Validate targets

    try:

        raw_targets = (
            [args.target]
            if args.target
            else args.targets.split(",")
        )

        targets = []

        for raw_ip in raw_targets:

            raw_ip = raw_ip.strip()

            if not raw_ip:
                raise ValueError("Empty IP address")

            address = ipaddress.ip_address(raw_ip)

            if address.version != 4:
                raise ValueError("Only IPv4 is supported")

            normalized = str(address)

            if normalized not in targets:
                targets.append(normalized)

        if len(targets) > MAX_TARGETS:
            raise ValueError("Maximum 20 targets allowed")

    except ValueError as error:

        parser.error(str(error))

    # Validate threads

    if not 1 <= args.threads <= MAX_ALLOWED_THREADS:
        parser.error("Threads must be between 1 and 500")

    # Validate timeout

    if not 0.1 <= args.timeout <= 10:
        parser.error("Timeout must be between 0.1 and 10 seconds")

    start_port, end_port = args.ports

    ports_per_target = end_port - start_port + 1

    total_scans = len(targets) * ports_per_target

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S_%f"
    )

    scan_started = datetime.now()

    print("\n" + "=" * 75)
    print(" ADVANCED NETWORK PORT & SERVICE SCANNER")
    print("=" * 75)

    print("Targets:", ", ".join(targets))
    print("Number of targets:", len(targets))
    print("Port range:", f"{start_port}-{end_port}")
    print("Total ports:", total_scans)
    print("Threads:", args.threads)
    print("Timeout:", args.timeout)
    print("Start time:", scan_started)

    print("=" * 75)

    results = []
    errors = []

    completed = 0
    interrupted = False

    start_time = time.perf_counter()

    logger.info("Scan started")
    logger.info("Targets: %s", ", ".join(targets))
    logger.info("Port range: %s-%s", start_port, end_port)
    logger.info("Total ports requested: %s", total_scans)

    executor = ThreadPoolExecutor(
        max_workers=args.threads
    )

    futures = []
    future_details = {}

    try:

        print("\n[+] Scanning started...\n")

        for target in targets:

            for port in range(start_port, end_port + 1):

                future = executor.submit(
                    scan_port,
                    target,
                    port,
                    args.timeout
                )

                futures.append(future)
                future_details[future] = (target, port)

        for future in as_completed(futures):

            completed += 1

            try:

                result = future.result()

                if result:

                    if result["status"] == "open":
                        results.append(result)
                        logger.info(
                            "OPEN: %s:%s - %s",
                            result["target"], result["port"],
                            result["service"]
                        )

                    else:
                        errors.append({
                            "target": result["target"],
                            "port": result["port"],
                            "error": result["error"]
                        })
                        logger.warning(
                            "ERROR: %s:%s - %s",
                            result["target"], result["port"],
                            result["error"]
                        )

            except Exception as error:

                target, port = future_details.get(
                    future, ("unknown", 0)
                )

                errors.append({
                    "target": target,
                    "port": port,
                    "error": f"Unexpected task error: {error}"
                })

                logger.exception(
                    "Unexpected task error at %s:%s",
                    target, port
                )

                print("\n[!] Unexpected task error:", error)

            display_progress(
                completed,
                total_scans,
                len(results),
                len(errors),
                start_time
            )

    except KeyboardInterrupt:

        interrupted = True

        print("\n\n[!] Scan interrupted by user.")

        for future in futures:
            future.cancel()

    finally:

        executor.shutdown(
            wait=True,
            cancel_futures=True
        )

    results.sort(
        key=lambda item: (
            item["target"],
            item["port"]
        )
    )

    errors.sort(
        key=lambda item: (
            item["target"],
            item["port"]
        )
    )

    end_time = time.perf_counter()

    scan_completed = datetime.now()

    duration = round(
        end_time - start_time,
        4
    )

    logger.info(
        "Scan completed. Open ports: %s, Errors: %s, Duration: %s seconds",
        len(results), len(errors), duration
    )

    closed_count = (
        completed - len(results) - len(errors)
    )

    # Final scan results

    print("\n" + "=" * 75)
    print(" SCAN RESULTS")
    print("=" * 75)

    if results:

        for item in results:

            print(
                f"\n[OPEN] {item['target']}:{item['port']}"
            )

            print("Service:", item["service"])
            print("Registered service:", item["registered_service"])
            print("Banner:", item["banner"])

    else:

        print("No open ports found.")

    # Error summary

    print("\n" + "=" * 75)
    print(" ERROR SUMMARY")
    print("=" * 75)

    print("Connection errors:", len(errors))

    if errors:

        for item in errors[:20]:

            print(
                f"{item['target']}:{item['port']} "
                f"- {item['error']}"
            )

        if len(errors) > 20:
            print("Additional errors saved in the error report.")

    # Generate reports

    save_json_report(
        results,
        errors,
        targets,
        scan_started.isoformat(),
        scan_completed.isoformat(),
        timestamp,
        completed,
        duration,
        interrupted
    )

    save_csv_report(
        results,
        timestamp
    )

    save_error_report(
        errors,
        timestamp
    )

    # Final statistics

    print("\n" + "=" * 75)
    print(" FINAL SCAN STATISTICS")
    print("=" * 75)

    print("Targets:", len(targets))
    print("Total ports requested:", total_scans)
    print("Ports completed:", completed)
    print("Ports remaining:", total_scans - completed)
    print("Open ports:", len(results))
    print("Closed ports:", closed_count)
    print("Errors:", len(errors))
    print("Scan duration:", duration, "seconds")

    if duration > 0:
        print(
            "Average speed:",
            round(completed / duration, 2),
            "ports/second"
        )

    print("Interrupted:", interrupted)

    print("=" * 75)

    if interrupted:
        print("[!] Partial scan reports saved.")
    else:
        print("[+] Scan completed successfully.")


# ==================================================
# PROGRAM ENTRY POINT
# ==================================================

if __name__ == "__main__":

    try:
        main()

    except KeyboardInterrupt:
        print("\n[!] Scanner stopped safely.")
