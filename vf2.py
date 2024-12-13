import os
import argparse
import subprocess
import ipaddress

def run_nmap_scan(network):
    try:
        result = subprocess.run([
            "nmap", "-sn", network
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout
    except Exception as e:
        print(f"[!] Hata: {e}")
        return ""

def parse_nmap_output(output):
    active_vlans = []
    for line in output.splitlines():
        if "Host is up" in line:
            previous_line = output.splitlines()[output.splitlines().index(line) - 1]
            if previous_line.startswith("Nmap scan report for"):
                vlan = previous_line.split()[-1]
                active_vlans.append(vlan)
    return active_vlans

def save_progress(file_path, current_network):
    with open(file_path, "w") as f:
        f.write(current_network)

def load_progress(file_path):
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            return f.read().strip()
    return None

def scan_vlans(output_file, progress_file, vlan_output_file):
    print("[+] VLAN Taraması Başlatılıyor...")
    base_network = ipaddress.ip_network("10.0.0.0/8")
    active_vlans = []

    # Load progress
    start_network = load_progress(progress_file)
    start_network = ipaddress.ip_network(start_network) if start_network else None

    for /16 subnet in base_network.subnets(new_prefix=16):
        for /24 subnet in subnet.subnets(new_prefix=24):
            if start_network and subnet < start_network:
                continue  # Skip completed subnets

            print(f"[+] Taranıyor: {subnet}")
            output = run_nmap_scan(str(subnet))
            active_vlans.extend(parse_nmap_output(output))

            # Save progress
            save_progress(progress_file, str(subnet))

    print("\n[+] Tarama Tamamlandı.")

    # Save active VLANs
    print(f"[+] Aktif VLAN'lar dosyaya yazılıyor: {vlan_output_file}")
    with open(vlan_output_file, "w") as f:
        for vlan in active_vlans:
            f.write(f"{vlan}\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Nmap ile VLAN Taraması")
    parser.add_argument("-o", "--output", required=True, help="Aktif VLAN'ların kaydedileceği dosya yolu")
    parser.add_argument("-p", "--progress", required=True, help="Durum bilgisinin kaydedileceği dosya yolu")
    args = parser.parse_args()

    # Kontrol için root yetkisi gerekliliği
    if os.geteuid() != 0:
        print("[!] Bu aracı çalıştırmak için root yetkisi gereklidir.")
        exit(1)

    scan_vlans(args.output, args.progress, args.output)
