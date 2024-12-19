import nmap
import argparse
import sys
import subprocess
import random
from concurrent.futures import ThreadPoolExecutor

def change_mac(interface):
    """Changes the MAC address of the specified interface to a random one."""
    new_mac = "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0, 255) for _ in range(5))
    try:
        subprocess.run(["sudo", "ifconfig", interface, "down"], check=True)
        subprocess.run(["sudo", "ifconfig", interface, "hw", "ether", new_mac], check=True)
        subprocess.run(["sudo", "ifconfig", interface, "up"], check=True)
        print(f"MAC address changed to {new_mac} on interface {interface}")
    except Exception as e:
        print(f"Failed to change MAC address: {e}")

def change_ip(interface, ip_range):
    """Changes the IP address of the specified interface to a random one within the given range."""
    start_ip, end_ip = [list(map(int, ip.split("."))) for ip in ip_range.split("-")]
    random_ip = ".".join(str(random.randint(start_ip[i], end_ip[i])) for i in range(4))
    try:
        subprocess.run(["sudo", "ifconfig", interface, random_ip, "netmask", "255.255.255.0"], check=True)
        print(f"IP address changed to {random_ip} on interface {interface}")
    except Exception as e:
        print(f"Failed to change IP address: {e}")

def read_targets(file_path):
    """Reads the IP/subnet list from a file."""
    try:
        with open(file_path, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
        return targets
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)

def check_port_open(scanner, host, ports):
    """Checks if any of the specified ports are open on a host."""
    open_ports = []
    try:
        scan_result = scanner.scan(hosts=host, ports=ports, arguments="-Pn")
        for port in ports.split(','):
            port = int(port.strip())
            try:
                state = scan_result["scan"][host]["tcp"][port]["state"]
                if state == "open":
                    open_ports.append(port)
            except KeyError:
                pass
        return open_ports
    except Exception as e:
        print(f"Error checking ports on {host}: {e}")
        return []

def scan_host(target, ports, smb_ports, smb_scripts, scanner, output_file):
    """Scans a single host for specified ports and SMB scripts."""
    print(f"Checking {target} for ports {ports}...")
    open_ports = check_port_open(scanner, target, ports)
    if not open_ports:
        print(f"No specified ports are open on {target}. Skipping...")
        return

    for smb_port in smb_ports:
        if smb_port in open_ports:
            print(f"Scanning {target} on SMB port {smb_port}...")
            try:
                script_arguments = f"--script {','.join(smb_scripts)}"
                scan_result = scanner.scan(
                    hosts=target,
                    ports=str(smb_port),
                    arguments=script_arguments
                )
                # Append Nmap output to the file
                with open(output_file, 'a') as f:
                    f.write(scanner.command_line() + "\n")
                    f.write(scanner.csv() + "\n")
            except Exception as e:
                print(f"Error scanning {target} on port {smb_port}: {e}")

def smb_scan_parallel(targets, ports, output_file, max_threads, interface, ip_range, packet_limit):
    """Scans targets in parallel for SMB services and changes MAC/IP after a packet limit."""
    scanner = nmap.PortScanner()
    smb_ports = [139, 445]
    smb_scripts = [
        "smb-enum-shares",
        "smb-enum-users",
        "smb-enum-sessions",
        "smb-os-discovery"
    ]

    packet_count = 0

    def process_target(target):
        """Wrapper for parallel processing of a single target."""
        nonlocal packet_count
        packet_count += 1

        # Change MAC and IP after packet_limit is reached
        if packet_count >= packet_limit:
            change_mac(interface)
            change_ip(interface, ip_range)
            packet_count = 0

        scan_host(target, ports, smb_ports, smb_scripts, scanner, output_file)

    # Use ThreadPoolExecutor for parallel scanning
    with ThreadPoolExecutor(max_threads) as executor:
        executor.map(process_target, targets)

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="SMB Enumeration Scanner with MAC/IP Rotation")
    parser.add_argument("-i", "--input", required=True, help="Path to the file containing IP/subnet list")
    parser.add_argument("-p", "--ports", required=True, help="Comma-separated list of ports to check (e.g., 80,443,8080)")
    parser.add_argument("-o", "--output", required=True, help="Output file path to save results")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of parallel threads (default: 5)")
    parser.add_argument("-n", "--interface", required=True, help="Network interface for MAC/IP changes (e.g., eth0)")
    parser.add_argument("-r", "--ip-range", required=True, help="IP range for random IP assignment (e.g., 192.168.1.100-192.168.1.200)")
    parser.add_argument("-l", "--packet-limit", type=int, default=50, help="Number of packets before MAC/IP rotation (default: 50)")

    args = parser.parse_args()

    # Read targets and perform scan
    targets = read_targets(args.input)
    smb_scan_parallel(targets, args.ports, args.output, args.threads, args.interface, args.ip_range, args.packet_limit)

if __name__ == "__main__":
    main()
