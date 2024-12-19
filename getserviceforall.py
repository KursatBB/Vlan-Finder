import nmap
import argparse
import sys

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

def smb_scan(targets, ports, output_file):
    """Scans the targets for SMB services with multiple scripts."""
    scanner = nmap.PortScanner()
    results = []

    smb_ports = [139, 445]
    smb_scripts = [
        "smb-enum-shares",
        "smb-enum-users",
        "smb-enum-sessions",
        "smb-os-discovery"
    ]
    script_arguments = f"--script {','.join(smb_scripts)}"

    for target in targets:
        print(f"Checking {target} for ports {ports}...")
        open_ports = check_port_open(scanner, target, ports)
        if not open_ports:
            print(f"No specified ports are open on {target}. Skipping...")
            continue

        for smb_port in smb_ports:
            print(f"Checking {target} for SMB port {smb_port}...")
            if smb_port in open_ports:
                print(f"Scanning {target} on SMB port {smb_port}...")
                try:
                    scan_result = scanner.scan(
                        hosts=target,
                        ports=str(smb_port),
                        arguments=script_arguments
                    )
                    results.append(scan_result)
                except Exception as e:
                    print(f"Error scanning {target} on port {smb_port}: {e}")
            else:
                print(f"SMB port {smb_port} is closed on {target}.")

    # Save results to output file
    try:
        with open(output_file, 'w') as f:
            for result in results:
                f.write(f"{result}\n")
        print(f"Scan results saved to {output_file}")
    except Exception as e:
        print(f"Error writing to file: {e}")

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="SMB Enumeration Scanner")
    parser.add_argument("-i", "--input", required=True, help="Path to the file containing IP/subnet list")
    parser.add_argument("-p", "--ports", required=True, help="Comma-separated list of ports to check (e.g., 80,443,8080)")
    parser.add_argument("-o", "--output", required=True, help="Output file path to save results")

    args = parser.parse_args()

    # Read targets and perform scan
    targets = read_targets(args.input)
    smb_scan(targets, args.ports, args.output)

if __name__ == "__main__":
    main()
