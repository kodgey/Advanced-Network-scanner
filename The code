""""The Egyptian Scanner is an advanced network port scanning tool for security professionals and system administrators.
 It offers flexible target specification, customizable port selection, multi-threaded scanning, service identification,
banner grabbing, traceroute functionality, rate limiting, detailed logging, result export, error handling, user-friendly CLI,and
reminders for responsible usage.
It's designed for legitimate network auditing and security testing, emphasizing authorized and ethical use."""


import argparse # For parsing command-line arguments
import csv # For writing results to CSV files
import ipaddress # For handling IP addresses and networks
import json # For writing results to JSON files
import logging  # For logging information and errors
import os # For file and path operations
import socket # For network operations
import sys # For system-specific parameters and functions
import time # For adding delays
import signal # For handling interrupts
import random # For generating random numbers
from concurrent.futures import ThreadPoolExecutor, as_completed #For parallel execution of tasks, Import as_completed here for better readability
import subprocess # For running system commands
from functools import wraps # For creating decorator functions
from typing import Optional # For type hinting
from typing import Optional, List, Dict, Tuple # Additional type hinting imports


# Print ASCII art banner
print(r"""          _____ _            _____                  _   _
         |_   _| |__   ___  | ____|__ _ _   _ _ __ | |_(_) __  _ __
           | | | '_ \ / _ \ |  _| / _` | | | | '_ \| __| |/ _` | '_ \
           | | | | | |  __/ | |__| (_| | |_| | |_) | |_| | (_| | | | |
           |_| |_| |_|\___| |_____\__, |\__, | .__/ \__|_|\__,_|_| |_|
                                  |___/ |___/|_|
                     ____
                    / ___|  ___ __ _ _ __  _ __   ___ _ __
                    \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
                     ___) | (_| (_| | | | | | | |  __/ |
                    |____/ \___\__,_|_| |_|_| |_|\___|_|
""")
# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__) # Create a logger instance


def parse_arguments():# Set up command-line argument parser
    parser = argparse.ArgumentParser(description="Advanced Network Security Scanner")# Create an argument parser
    parser.add_argument("targets", help="IP address, range (CIDR notation), or file containing IP addresses")# Add targets argument
    parser.add_argument("-f", "--file", action="store_true", help="Specify that the targets argument is a file path")# Add file flag
    parser.add_argument("-p", "--ports", default="1-1024", help="Comma-separated list of ports or ranges to scan (default: 1-65535)") # Add ports argument
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of threads to use (default: 100)")# Add threads argument
    parser.add_argument("-o", "--output", action='store_true', help="Generate output with default filename 'scan_results'")# Add output flag
    parser.add_argument("--timeout", type=float, default=1.0, help="Timeout for connections in seconds (default: 1.0)")# Add timeout argument
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between each connection attempt in seconds (default: 0.0)")# Add delay argument
    parser.add_argument("--traceroute", action="store_true", help="Perform traceroute to targets")# Add traceroute flag
    return parser.parse_args()# Parse and return the arguments

def expand_targets(targets, is_file=False):# If targets is a file or a file path, read IP addresses from the file
    if is_file or os.path.isfile(targets):
        with open(targets, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    try:# Try to interpret targets as a CIDR range
        return [str(ip) for ip in ipaddress.IPv4Network(targets, strict=False)]
    except ValueError: # If it's not a CIDR range, return it as a single IP in a list
        return [targets]
    # If targets is a CIDR range, expand it
    try:
        return [str(ip) for ip in ipaddress.IPv4Network(targets, strict=False)]
    except ValueError:
        # If it's a single IP, return it as a list
        return [targets]

def parse_port_range(port_range, num_random_ports=0):
    ports = set()  # Using a set to avoid duplicates
    for part in port_range.split(","): # Parse comma-separated port ranges
        part = part.strip()
        if '-' in part:
            # Handle port ranges (e.g., 80-100)
            try:
                start, end = map(int, part.split('-'))
                ports.update(range(start, end + 1))
            except ValueError:
                logger.error(f"Invalid port range: {part}")
        else:
            # Handle single ports
            try:
                ports.add(int(part))
            except ValueError:
                logger.error(f"Invalid port number: {part}")
    # Add random ports if specified
    if num_random_ports > 0:
        while len(ports) < num_random_ports:
            ports.add(random.randint(1, 65535))

    return sorted(ports)  # Return a sorted list of ports

class RateLimiter: #basic rate limiting mechanism
    def __init__(self, max_calls, time_frame):
        self.max_calls = max_calls # Maximum number of calls allowed in the time frame
        self.time_frame = time_frame  # Time frame in seconds
        self.calls = []  # List to store timestamps of calls

    def __call__(self, func):
        @wraps(func) # Preserve metadata of the original function
        def wrapper(*args, **kwargs):
            now = time.monotonic() # Get current time
            # Remove old calls that are outside the time frame
            self.calls = [call for call in self.calls if now - call < self.time_frame]
            if len(self.calls) >= self.max_calls: # If max calls reached, calculate sleep time
                sleep_time = self.calls[0] + self.time_frame - now
                if sleep_time > 0:
                    time.sleep(sleep_time) # Sleep to respect rate limit
            result = func(*args, **kwargs) # Call the original function
            self.calls.append(time.monotonic()) # Record this call
            return result
        return wrapper # Return the wrapped function

def respect_target_constraints(ip, ports, max_ports_per_scan=100):
    if len(ports) > max_ports_per_scan: # Check if the number of ports to scan exceeds the maximum allowed
        logging.warning(f"Limiting scan to {max_ports_per_scan} ports for {ip}") # Log a warning message if the number of ports is being limited
        return random.sample(ports, max_ports_per_scan) # Randomly select a subset of ports equal to max_ports_per_scan
    return ports # If the number of ports doesn't exceed the limit, return all ports

def scan_port(ip, port, timeout):
    rate_limiter(max_calls=200, time_frame=120)  # 200 calls per 120 seconds
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            return True # Port is open
    except (socket.timeout, ConnectionRefusedError):
        return False # Port is closed
    except Exception as e:
        logger.error(f"Error scanning {ip}:{port}: {e}")
        return False

def grab_banner(ip: str, port: int, timeout: float) -> str:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            # Receive data from the socket
            banner_data = sock.recv(1024)  # Adjust based on expected banner size
            # Attempt to decode the banner
            try:
                banner = banner_data.decode('utf-8').strip()
            except UnicodeDecodeError:
                logging.warning(f"Failed to decode banner from {ip}:{port}. Data may not be UTF-8 encoded.")
                banner = banner_data.decode(errors='ignore').strip()  # Fallback to ignore unknown bytes
            return banner
    except (socket.timeout, ConnectionRefusedError) as e:
        logging.error(f"Connection failed for {ip}:{port} - {str(e)}")
        return ""
    except Exception as e:
        logging.exception(f"An unexpected error occurred while grabbing banner from {ip}:{port}: {str(e)}")
        return ""


def identify_service(port: int, banner: str) -> str: # Dictionary of known ports and their associated services
    known_ports = {
        1: "TCPMUX", 5: "RJE", 7: "ECHO Protocol", 9: "DISCARD Protocol", 11: "systat service", 13: "DAYTIME Protocol", 17: "QOTD",
        18: "MSP",19: "CHARGEN", 20: "FTP Data Transfer", 21: "FTP Control", 22: "SSH", 23: "Telnet", 25: "SMTP", 37: "Time Protocol",
        39: "RLP", 42: "Nameserv", 43: "WHOIS Protocol", 49: "TACACS", 53: "DNS",
        67: "BOOTP Server/DHCP", 68: "BOOTP Client/DHCP", 69: "TFTP", 70: "Gopher Protocol", 79: "Finger Protocol",
        80: "HTTP", 88: "KAS", 102: "TSAP", 110: "POP3", 111: "RPC", 113: "Ident", 119: "NNTP", 123: "NTP", 135: "RPC",
        137: "NetBIOS Service", 138: "NetBIOS Datagram Service", 139: "NetBIOS Session Service", 143: "IMAP", 161: "SNMP",
        162: "SNMPTRAP", 179: "BGP", 194: "IRC", 389: "LDAP", 443: "HTTPS", 445: "Microsoft AD",
        464: "Kerberos Change/Set password", 465: "SMTP over TLS/SSL, SSM (SMTPS)", 500: "ISAKMP/IKE", 514: "Rsh", 515: "LPD",
        520: "RIP", 521: "RIPng", 540: "UUCP", 554: "RTSP", 587: "SMTP", 631: "IPP", 636: "TLS/SSL(LDAPS)",
        989: "FTP over TLS/SSL (FTPS) data transfer",
        990: "FTP over TLS/SSL (FTPS) control",
        993: "Internet Message Access Protocol over TLS/SSL (IMAPS)",
        995: "Post Office Protocol 3 over TLS/SSL (POP3S)",
        1080: "SOCKS Proxy",
        1194: "OpenVPN",
        1433: "Microsoft SQL Server",
        1434: "Microsoft SQL Server Browser service",
        1521: "Oracle database default listener",
        1701: "Layer 2 Forwarding Protocol (L2F) / Layer 2 Tunneling Protocol (L2TP)",
        1720: "H.323 call signaling",
        1723: "Point-to-Point Tunneling Protocol (PPTP)",
        2049: "Network File System (NFS)",
        3306: "MySQL database system",
        3389: "Remote Desktop Protocol (RDP)",
        5060: "Session Initiation Protocol (SIP)",
        5061: "Session Initiation Protocol (SIP) over TLS",
        5355: "Link-Local Multicast Name Resolution (LLMNR)",
        5432: "PostgreSQL database system",
        5900: "Virtual Network Computing (VNC) Remote Frame Buffer (RFB) protocol",
        6379: "Redis key-value data store",
        8080: "HTTP Alternate (http_alt) - commonly used for web proxies and caching servers",
        9100: "PDL Data Stream, used for printing to network printers",
        27017: "MongoDB database system"
    }
    # Check if the port is in the known_ports dictionary
    if port in known_ports:
        return known_ports[port]

    # Check banner for common service signatures
    banner_lower = banner.lower()
    if "ssh" in banner_lower:
        return "SSH (Secure Shell)"
    elif "http" in banner_lower:
        return "HTTP (Hypertext Transfer Protocol)"
    elif "ftp" in banner_lower:
        return "FTP (File Transfer Protocol)"
    elif "smtp" in banner_lower:
        return "SMTP (Simple Mail Transfer Protocol)"
    elif "pop3" in banner_lower:
        return "POP3 (Post Office Protocol version 3)"
    elif "imap" in banner_lower:
        return "IMAP (Internet Message Access Protocol)"
    elif "telnet" in banner_lower:
        return "Telnet"
    elif "mysql" in banner_lower:
        return "MySQL Database"
    elif "postgresql" in banner_lower:
        return "PostgreSQL Database"
    elif "mongodb" in banner_lower:
        return "MongoDB Database"
    elif "redis" in banner_lower:
        return "Redis Data Store"
    elif "vnc" in banner_lower:
        return "VNC (Virtual Network Computing)"
    return f"Unknown Service on Port {port}"
def scan_target(ip, ports, timeout, delay):# Initialize list to store scan results
    results = []
    for port in ports:# Iterate through each port
        if delay > 0:
            time.sleep(delay) # Add delay between port scans if specified
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:# Create a TCP socket
                sock.settimeout(timeout) # Set socket timeout
                result = sock.connect_ex((ip, port)) # Attempt to connect to the port
                if result == 0:# If connection successful (port is open)
                    banner = grab_banner(ip, port, timeout) # Try to grab the service banner
                    service = identify_service(port, banner) # Identify the service
                    results.append((ip, port, "open", service, banner)) # Add open port to results
                    logger.info(f"Open port found: {ip}:{port} - {service}") # Log open port
                else:# If connection failed (port is closed)
                    results.append((ip, port, "closed", "", "")) # Add closed port to results
                    logger.info(f"Closed port found: {ip}:{port}") # Log closed port
        except Exception as e: # Handle any exceptions during scanning
            logger.error(f"Error scanning {ip}:{port}: {e}") # Log the error
            results.append((ip, port, "error", str(e), "")) # Add error to results
    return results # Return all results for this target

def scan_all_targets(targets, ports, threads, timeout, delay):
    all_results = []  # Initialize list to store all scan results
    with ThreadPoolExecutor(max_workers=threads) as executor:  # Create a thread pool
        # Submit scan jobs to thread pool
        future_to_ip = {executor.submit(scan_target, ip, respect_target_constraints(ip, ports), timeout, delay): ip for ip in targets}
        try:
            for future in as_completed(future_to_ip): # As each job completes
                ip = future_to_ip[future] # Get the IP associated with this job
                try:
                    results = future.result() # Get the results of this job
                    all_results.extend(results) # Add results to overall results list
                except Exception as exc: # Handle any exceptions from the job
                    logger.error(f'{ip} generated an exception: {exc}') # Log the error
        except KeyboardInterrupt: # Handle keyboard interrupt (Ctrl+C)
            logger.info("Keyboard interrupt detected. Cancelling tasks...") # Log the interrupt
            for f in future_to_ip: # Cancel all pending tasks
                f.cancel()
    return all_results

def traceroute(ip):
    logger.debug(f"Starting traceroute to {ip}")
    try: # Run the tracert command and capture its output
        output = subprocess.check_output(['tracert', '-d', ip], universal_newlines=True, timeout=30)
        lines = output.split('\n') # Split the output into lines
        hops = [] # Initialize an empty list to store hop addresses
        # Process each line of the output, skipping header and footer
        for line in lines[4:-2]: # Skip header and footer lines
            parts = line.split()
            if len(parts) >= 8:
                hop = parts[7]
                if hop == 'Request':
                    hop = '*' # Replace 'Request timed out' with *
                hops.append(hop)
        hop_count = len(hops)  # Count the number of hops (not used in this function)
        return ' -> '.join(hops)  # Join all hops into a single string, separated by ' -> '
    except subprocess.CalledProcessError as e:
        return f"Traceroute error: {e}"
    except subprocess.TimeoutExpired:
        return "Traceroute timed out"


def print_results(results, traceroute_results):
    # Print header for scan results
    print("\nScan Results:")
    print("=" * 100)  # Print a line of 100 equal signs for formatting

    # Print column headers
    print(f"{'IP Address':<15} {'Port':<6} {'Status':<8} {'Service':<15} {'Banner':<20} {'Traceroute'}")
    print("-" * 100)  # Print a line of 80 dashes to separate headers from results
    # Iterate through each result
    for ip, port, status, service, banner in results:
        # Get traceroute result for this IP, or 'N/A' if not available
        traceroute = traceroute_results.get(ip, 'N/A')
        # Print formatted result line
        print(f"{ip:<15} {port:<6} {status:<8} {service:<15} {banner[:20]:<20} {traceroute[:30]}...")
    # Print footer
    print("=" * 100)  # Print a line of 80 equal signs to close the results table

def get_writable_filename(base_name: str, extension: str) -> str:
    #For unique filename for writing output
    counter = 0 # Initialize a counter for filename versioning
    while True: # Loop until a unique filename is found
        if counter == 0: # If it's the first attempt, use the base name and extension as is
            filename = f"{base_name}.{extension}"
        else:
            filename = f"{base_name}_{counter}.{extension}"  # For subsequent attempts, append a counter to the base name

        if not os.path.exists(filename):  # Check if a file with this name already exists
            return filename   # If the file doesn't exist, we've found a unique name, so return it
        counter += 1 # If the file exists, increment the counter and try again

def save_results(results: List[Tuple[str, int, str, str, str]], traceroute_results: Dict[str, str], should_output: bool):
    # Always print results to command line
    print_results(results, traceroute_results)

    # If output is not requested, return after printing to console
    if not should_output:
        return

    base_name = "scan_results"

    try:
        # Save results to CSV file
        csv_filename = get_writable_filename(base_name, "csv")
        with open(csv_filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            # Write header row
            writer.writerow(["IP", "Port", "Status", "Service", "Banner", "Traceroute"])
            # Write data rows
            for ip, port, status, service, banner in results:
                traceroute = traceroute_results.get(ip, 'N/A')
                writer.writerow([ip, port, status, service, banner, traceroute])
        logger.info(f"Results exported to {csv_filename}")

        # Save results to JSON file
        json_filename = get_writable_filename(base_name, "json")
        json_results = [
            {
                "ip": ip,
                "port": port,
                "status": status,
                "service": service,
                "banner": banner,
                "traceroute": traceroute_results.get(ip, 'N/A')
            }
            for ip, port, status, service, banner in results
        ]
        with open(json_filename, 'w') as jsonfile:
            json.dump(json_results, jsonfile, indent=2)
        logger.info(f"Results exported to {json_filename}")

    except PermissionError:
        # Handle permission errors when writing files
        logger.error("Permission denied when trying to write output files.")
        print("Error: Unable to write output files. Please check your permissions or choose a different directory.")
        print("Tip: You can redirect output to a writable location using '>' operator:")
        print(f"     python script.py [args] > {base_name}.txt")
    except IOError as e:
        # Handle I/O errors
        logger.error(f"IO error occurred: {e}")
        print(f"Error: Unable to write output files. {e}")
    except Exception as e:
        # Handle any other unexpected errors
        logger.error(f"Unexpected error occurred while saving results: {e}")
        print(f"Error: An unexpected problem occurred while saving results. {e}")


def run_scan(targets, ports, threads, timeout, delay, traceroute_enabled, output):
    # Perform the port scan on all targets
    results = scan_all_targets(targets, ports, threads, timeout, delay)

    # Initialize an empty dictionary to store traceroute results
    traceroute_results = {}

    # If traceroute is enabled, perform traceroute for each target
    if traceroute_enabled:
        for target in targets:
            logger.info(f"Performing traceroute to {target}")
            traceroute_results[target] = traceroute(target)

    # Log completion of the scan
    logger.info(f"Scan complete. Found open ports for {len(targets)} target(s).")

    # Save the results (this will also print them to console)
    save_results(results, traceroute_results, output)


def signal_handler(sig, frame):
    # This function is called when a SIGINT signal is received (e.g., when Ctrl+C is pressed)
    print("\nCtrl+C pressed. Stopping the scan...")
    # Exit the program
    sys.exit(0)

def main():
    # Set up signal handler for graceful termination on Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)

    # Print ASCII art and disclaimer
    print(r"""
    Advanced Network Port Scanner
    =================================
    """)
    print("DISCLAIMER: Use this tool responsibly and only on networks you have permission to scan.")

    # Parse command-line arguments
    args = parse_arguments()

    # Expand target IPs/ranges and parse port ranges
    targets = expand_targets(args.targets, args.file)
    ports = parse_port_range(args.ports)

    # Create a string representation of ports for filename
    port_string = ",".join(map(str, ports))
    output_filename = f"scan_results_ports_{port_string}"

    # Log the start of the scan
    logger.info(f"Starting scan of {len(targets)} target(s) on {len(ports)} port(s)")

    # Set output filename if output is enabled
    output_filename = "scan_results" if args.output else None

    # Perform initial traceroute if enabled
    if args.traceroute:
        for target in targets:
            print(f"\nTraceroute to {target}:")
            for hop, addr in enumerate(traceroute(target), start=1):
                if addr is None:
                    print(f"{hop}: *")
                else:
                    print(f"{hop}: {addr}")

    # Perform the main scan
    results = scan_all_targets(targets, ports, args.threads, args.timeout, args.delay)

    # Perform post-scan traceroute if enabled
    traceroute_results = {}
    if args.traceroute:
        for target in targets:
            logger.info(f"Performing traceroute to {target}")
            traceroute_results[target] = traceroute(target)

    # Log completion of the scan
    logger.info(f"Scan complete. Found open ports for {len(targets)} target(s).")

    # Save and display results
    save_results(results, traceroute_results, output_filename)

    # Print closing messages
    print("Thank you for using the Egyptian Port Scanner.")
    print("The scan result file will appear in the same directory as this Python file.")

# Entry point of the script
if __name__ == "__main__":
    main()
