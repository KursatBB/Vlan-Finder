import nmap
import argparse
import sys
import subprocess
import random
from concurrent.futures import ThreadPoolExecutor
from time import sleep

def reset_interface(interface):
    """Takes down and brings up the specified interface."""
    try:
        subprocess.run(["sudo", "ifconfig", interface, "down"], check=True)
        sleep(1)  # Allow time for the interface to go down
        subprocess.run(["sudo", "ifconfig", interface, "up"], check=True)
        print(f"Interface {interface} reset successfully.")
    except Exception as e:
        print(f"Failed to reset interface {interface}: {e}")

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

def scan_host(target, ports, smb_ports, smb_scripts, rdp_ports, rdp_scripts, scanner, output_file):
    """Scans a single host for specified ports and SMB/RDP scripts."""
    print(f"Checking {target} for ports {ports}...")
    open_ports = check_port_open(scanner, target, ports)
    if not open_ports:
        print(f"No specified ports are open on {target}. Skipping...")
        return

    # SMB Scan
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

    # RDP Scan
    for rdp_port in rdp_ports:
        if rdp_port in open_ports:
            print(f"Scanning {target} on RDP port {rdp_port}...")
            try:
                script_arguments = f"--script {','.join(rdp_scripts)}"
                scan_result = scanner.scan(
                    hosts=target,
                    ports=str(rdp_port),
                    arguments=script_arguments
                )
                # Append Nmap output to the file
                with open(output_file, 'a') as f:
                    f.write(scanner.command_line() + "\n")
                    f.write(scanner.csv() + "\n")
            except Exception as e:
                print(f"Error scanning {target} on port {rdp_port}: {e}")

def smb_rdp_scan_parallel(targets, ports, output_file, max_threads, interface, packet_limit):
    """Scans targets in parallel for SMB and RDP services and pauses after a packet limit."""
    scanner = nmap.PortScanner()
    smb_ports = [139, 445]
    smb_scripts = [
        "smb-enum-shares",
        "smb-enum-users",
        "smb-enum-sessions",
        "smb-os-discovery"
    ]
    rdp_ports = [3389]
    rdp_scripts = [
        "rdp-enum-encryption",
        "rdp-vuln-ms12-020"
    ]

    packet_count = 0
    active_targets = iter(targets)

    def process_target(target):
        """Wrapper for processing a single target."""
        nonlocal packet_count
        packet_count += 1

        # Pause scanning and reset interface after reaching the packet limit
        if packet_count >= packet_limit:
            print(f"Packet limit ({packet_limit}) reached. Pausing...")
            reset_interface(interface)
            print("Resuming scanning...")
            packet_count = 0

        scan_host(target, ports, smb_ports, smb_scripts, rdp_ports, rdp_scripts, scanner, output_file)

    # Use ThreadPoolExecutor for parallel scanning
    with ThreadPoolExecutor(max_threads) as executor:
        executor.map(process_target, active_targets)

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="SMB and RDP Enumeration Scanner with Pause/Resume")
    parser.add_argument("-i", "--input", required=True, help="Path to the file containing IP/subnet list")
    parser.add_argument("-p", "--ports", required=True, help="Comma-separated list of ports to check (e.g., 80,443,8080)")
    parser.add_argument("-o", "--output", required=True, help="Output file path to save results")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of parallel threads (default: 5)")
    parser.add_argument("-n", "--interface", required=True, help="Network interface to reset (e.g., eth0)")
    parser.add_argument("-l", "--packet-limit", type=int, default=50, help="Number of packets before pausing (default: 50)")

    args = parser.parse_args()

    # Read targets and perform scan
    targets = read_targets(args.input)
    smb_rdp_scan_parallel(targets, args.ports, args.output, args.threads, args.interface, args.packet_limit)

if __name__ == "__main__":
    main()
