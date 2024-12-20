import nmap
import argparse
import sys
import subprocess
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

def determine_scripts(ports):
    """Determines Nmap scripts to run based on the given ports."""
    smb_scripts = [
        "smb-enum-shares",
        "smb-enum-users",
        "smb-enum-sessions",
        "smb-os-discovery"
    ]
    rdp_scripts = [
        "rdp-enum-encryption",
        "rdp-vuln-ms12-020",
        "rdp-ntlm-info"
    ]
    additional_scripts = []

    if "139" in ports or "445" in ports:
        additional_scripts.extend(smb_scripts)
    if "3389" in ports:
        additional_scripts.extend(rdp_scripts)

    return additional_scripts

def scan_target(target, ports, scanner, output_file, service_hosts, scripts):
    """Performs scanning on a single target with specified ports and scripts."""
    print(f"Scanning {target} for ports {ports}...")
    try:
        script_arguments = f"--script {','.join(scripts)}" if scripts else ""
        scan_result = scanner.scan(
            hosts=target,
            ports=ports,
            arguments=f"-Pn --open {script_arguments}"
        )
        # Save Nmap output to the main output file
        with open(output_file, 'a') as f:
            f.write(scanner.get_nmap_output())

        # Extract open services and add them to the shared dictionary
        target_service_hosts = extract_open_services(scan_result)
        for service, hosts in target_service_hosts.items():
            if service not in service_hosts:
                service_hosts[service] = []
            service_hosts[service].extend(hosts)

    except Exception as e:
        print(f"Error scanning {target}: {e}")

def extract_open_services(scan_result):
    """Extracts open services and associated hosts from the Nmap result."""
    service_hosts = {}
    for host, details in scan_result.get("scan", {}).items():
        for port, port_data in details.get("tcp", {}).items():
            if port_data.get("state") == "open":
                service = port_data.get("name", f"port_{port}")
                if service not in service_hosts:
                    service_hosts[service] = []
                service_hosts[service].append(host)
    return service_hosts

def write_service_hosts(service_hosts):
    """Writes service-specific host lists to separate files."""
    for service, hosts in service_hosts.items():
        file_name = f"{service}_hosts.txt"
        with open(file_name, "w") as f:
            for host in hosts:
                f.write(f"{host}\n")
        print(f"Saved hosts for service '{service}' to {file_name}")

def parallel_scan(targets, ports, output_file, max_threads, interface, hosts_limit, scripts):
    """Scans targets in parallel and resets interface after scanning a set number of hosts."""
    scanner = nmap.PortScanner()
    service_hosts = {}  # Shared dictionary for tracking service-specific hosts
    processed_hosts = 0  # Counter for processed hosts

    def process_target(target):
        """Wrapper for processing a single target."""
        nonlocal processed_hosts
        processed_hosts += 1

        # Reset interface after reaching the hosts limit
        if processed_hosts >= hosts_limit:
            print(f"Host limit ({hosts_limit}) reached. Resetting interface...")
            reset_interface(interface)
            processed_hosts = 0

        # Perform scan
        scan_target(target, ports, scanner, output_file, service_hosts, scripts)

    # Use ThreadPoolExecutor for parallel scanning
    with ThreadPoolExecutor(max_threads) as executor:
        executor.map(process_target, targets)

    # Write service-specific host lists after all scans
    write_service_hosts(service_hosts)

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Flexible Nmap Scanner with Service-Specific Host Lists")
    parser.add_argument("-i", "--input", required=True, help="Path to the file containing IP/subnet list")
    parser.add_argument("-p", "--ports", required=True, help="Comma-separated list of ports to scan (e.g., 80,443,3389)")
    parser.add_argument("-o", "--output", required=True, help="Output file path to save Nmap results")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of parallel threads (default: 5)")
    parser.add_argument("-n", "--interface", required=True, help="Network interface to reset (e.g., eth0)")
    parser.add_argument("-hl", "--hosts-limit", type=int, default=10, help="Number of hosts to scan before resetting interface (default: 10)")

    args = parser.parse_args()

    # Determine scripts based on ports
    port_list = args.ports.split(",")
    scripts = determine_scripts(port_list)

    # Read targets and perform scan
    targets = read_targets(args.input)
    parallel_scan(
        targets,
        args.ports,
        args.output,
        args.threads,
        args.interface,
        args.hosts_limit,
        scripts
    )

if __name__ == "__main__":
    main()
