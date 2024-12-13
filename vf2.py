import os
import argparse
import subprocess
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

def run_nmap_scan(network):
    try:
        result = subprocess.run([
            "nmap", "-sn", network
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(f"[+] Nmap taraması tamamlandı: {network}\nÇıktı:\n{result.stdout}")
        return result.stdout
    except Exception as e:
        print(f"[!] Hata: {e}")
        return ""

def parse_nmap_output_parallel(outputs):
    active_vlans = []

    def parse_output(output):
        temp_vlans = []
        for line in output.splitlines():
            if "Host is up" in line:
                previous_line = output.splitlines()[output.splitlines().index(line) - 1]
                if previous_line.startswith("Nmap scan report for"):
                    vlan = previous_line.split()[-1]
                    temp_vlans.append(vlan)
        return temp_vlans

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(parse_output, output) for output in outputs]
        for future in as_completed(futures):
            result = future.result()
            print(f"[+] Çıktı parse edildi: {result}")
            active_vlans.extend(result)

    return active_vlans

def save_progress(file_path, current_network):
    with open(file_path, "w") as f:
        f.write(current_network)

def load_progress(file_path):
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            return f.read().strip()
    return None

def scan_gateways(output_file, progress_file, vlan_output_file):
    print("[+] Gateway Taraması Başlatılıyor...")
    base_network = ipaddress.ip_network("10.0.0.0/8")
    active_vlans = []

    # Load progress
    start_network = load_progress(progress_file)
    start_network = ipaddress.ip_network(start_network) if start_network else None

    with ThreadPoolExecutor(max_workers=10) as executor:  # Paralel tarama için iş parçacığı sayısı
        scan_futures = {}

        for subnet_16 in base_network.subnets(new_prefix=16):
            for subnet_24 in subnet_16.subnets(new_prefix=24):
                if start_network and subnet_24 < start_network:
                    continue  # Skip completed subnets

                # Tarama için gateway IP'lerini belirle
                gateway_ips = [
                    str(subnet_24.network_address + 1),  # x.x.x.1
                    str(subnet_24.network_address + 254)  # x.x.x.254
                ]

                for gateway_ip in gateway_ips:
                    print(f"[+] Taranıyor: {gateway_ip}")
                    scan_futures[executor.submit(run_nmap_scan, gateway_ip)] = gateway_ip

        scan_outputs = []
        for future in as_completed(scan_futures):
            gateway_ip = scan_futures[future]
            try:
                output = future.result()
                print(f"[+] Nmap taraması tamamlandı: {gateway_ip}\nÇıktı:\n{output}")
                scan_outputs.append(output)
            except Exception as e:
                print(f"[!] Hata {gateway_ip} için: {e}")

            # Save progress
            last_subnet = str(subnet_24)
            save_progress(progress_file, last_subnet)

    print("\n[+] Tarama tamamlandı. Çıktılar işleniyor...")
    active_vlans = parse_nmap_output_parallel(scan_outputs)

    # Save active VLANs
    print(f"[+] Aktif VLAN'lar dosyaya yazılıyor: {vlan_output_file}")
    with open(vlan_output_file, "w") as f:
        for vlan in active_vlans:
            f.write(f"{vlan}\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Nmap ile Gateway Taraması")
    parser.add_argument("-o", "--output", required=True, help="Aktif VLAN'ların kaydedileceği dosya yolu")
    parser.add_argument("-p", "--progress", required=True, help="Durum bilgisinin kaydedileceği dosya yolu")
    args = parser.parse_args()

    # Kontrol için root yetkisi gerekliliği
    if os.geteuid() != 0:
        print("[!] Bu aracı çalıştırmak için root yetkisi gereklidir.")
        exit(1)

    scan_gateways(args.output, args.progress, args.output)
