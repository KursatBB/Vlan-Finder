import os
import argparse
import subprocess
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

def run_nmap_scan(subnet, nmap_output_file):
    """
    Belirtilen subnet için nmap -sn taraması yapar ve sonuçları kaydeder.
    """
    print(f"[+] Subnet taranıyor: {subnet}")
    try:
        result = subprocess.run([
            "nmap", "-sn", subnet
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        with open(nmap_output_file, "a") as f:
            f.write(f"[+] Nmap taraması tamamlandı: {subnet}\nÇıktı:\n{result.stdout}\n")
        print(f"[+] Taraması tamamlandı: {subnet}, sonuç dosyaya yazıldı.")
        return result.stdout
    except Exception as e:
        print(f"[!] Hata: {e}")
        return ""

def parse_nmap_output(nmap_output_file):
    """
    Nmap çıktı dosyasından aktif subnetleri ve hostları ayrıştırır.
    """
    active_subnets = set()
    active_hosts = set()
    with open(nmap_output_file, "r") as f:
        output = f.read()
        lines = output.splitlines()
        for i, line in enumerate(lines):
            if "Nmap scan report for" in line:
                host = line.replace("Nmap scan report for ", "").strip()
                active_hosts.add(host)
                # Subneti IP adresinden türet
                if "(" in host:  # Eğer hostname varsa (hostname (IP))
                    ip = host.split("(")[-1].strip(")")
                else:
                    ip = host
                try:
                    subnet = str(ipaddress.IPv4Address(ip)) + "/24"
                    active_subnets.add(subnet)
                except Exception:
                    continue
    return active_subnets, active_hosts

def save_to_file(file_path, data):
    """
    Verilen verileri belirtilen dosyaya kaydeder.
    """
    with open(file_path, "w") as f:
        for item in sorted(data):
            f.write(f"{item}\n")

def scan_networks(output_file_subnets, output_file_hosts, progress_file, nmap_output_file):
    print("[+] Ağ taraması başlatılıyor...")
    base_network = ipaddress.ip_network("10.0.0.0/8")

    # Durum yükleme
    start_network = load_progress(progress_file)
    start_network = ipaddress.ip_network(start_network) if start_network else None

    with ThreadPoolExecutor(max_workers=10) as executor:  # Paralel tarama için iş parçacığı sayısı
        scan_futures = {}

        for subnet_16 in base_network.subnets(new_prefix=16):
            for subnet_24 in subnet_16.subnets(new_prefix=24):
                if start_network and subnet_24 < start_network:
                    continue  # Önceden taranan subnetleri atla

                print(f"[+] Taranıyor: {subnet_24}")
                scan_futures[executor.submit(run_nmap_scan, str(subnet_24), nmap_output_file)] = str(subnet_24)

        for future in as_completed(scan_futures):
            subnet = scan_futures[future]
            try:
                future.result()
            except Exception as e:
                print(f"[!] Hata {subnet} için: {e}")

            # Durumu kaydet
            save_progress(progress_file, subnet)

    print("\n[+] Tarama tamamlandı. Çıktılar işleniyor...")
    active_subnets, active_hosts = parse_nmap_output(nmap_output_file)

    # Aktif subnetleri ve hostları kaydet
    print(f"[+] Aktif subnetler '{output_file_subnets}' dosyasına yazılıyor.")
    save_to_file(output_file_subnets, active_subnets)
    print(f"[+] Aktif hostlar '{output_file_hosts}' dosyasına yazılıyor.")
    save_to_file(output_file_hosts, active_hosts)

def save_progress(file_path, current_network):
    """
    Durumu kaydeder.
    """
    with open(file_path, "w") as f:
        f.write(current_network)

def load_progress(file_path):
    """
    Önceden kaydedilmiş durumu yükler.
    """
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            return f.read().strip()
    return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Nmap ile Ağ Taraması")
    parser.add_argument("-s", "--subnet-output", required=True, help="Aktif subnetlerin kaydedileceği dosya yolu")
    parser.add_argument("-ho", "--host-output", required=True, help="Aktif hostların kaydedileceği dosya yolu")
    parser.add_argument("-p", "--progress", required=True, help="Durum bilgisinin kaydedileceği dosya yolu")
    parser.add_argument("-n", "--nmap-output", required=True, help="Nmap tarama sonuçlarının kaydedileceği dosya yolu")
    args = parser.parse_args()

    # Kontrol için root yetkisi gerekliliği
    if os.geteuid() != 0:
        print("[!] Bu aracı çalıştırmak için root yetkisi gereklidir.")
        exit(1)

    scan_networks(args.subnet_output, args.host_output, args.progress, args.nmap_output)
