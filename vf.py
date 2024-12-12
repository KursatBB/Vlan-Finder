import os
import ipaddress
from concurrent.futures import ThreadPoolExecutor
import argparse
import subprocess

def is_host_alive(ip):
    try:
        result = subprocess.run(["ping", "-c", "1", "-W", "1", str(ip)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            print(f"[+] Aktif: {ip}")
            return ip
    except Exception as e:
        print(f"[!] Hata: {e}")
    return None

def generate_all_private_networks():
    networks = []
    # 10.0.0.0/8
    networks.append("10.0.0.0/8")
    # 172.16.0.0/12
    networks.append("172.16.0.0/12")
    # 192.168.0.0/16
    networks.append("192.168.0.0/16")
    return networks

def scan_private_networks(verbose):
    print("[+] Tüm yerel IP adresleri taranıyor...")
    networks = generate_all_private_networks()
    active_hosts = []

    with ThreadPoolExecutor(max_workers=100) as executor:
        for network in networks:
            net = ipaddress.ip_network(network, strict=False)
            print(f"[+] Tarama başlatıldı: {network}")
            futures = [executor.submit(is_host_alive, ip) for ip in net.hosts()]
            for future in futures:
                result = future.result()
                if result:
                    active_hosts.append(result)

    print("\n[+] Tarama tamamlandı.")
    print("[+] Aktif IP'ler:")
    for host in active_hosts:
        print(host)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Tüm Yerel IP Adreslerini Tarama Aracı")
    parser.add_argument("-v", "--verbose", action="store_true", help="Detaylı çıktı göster")
    args = parser.parse_args()

    # Kontrol için root yetkisi gerekliliği
    if os.geteuid() != 0:
        print("[!] Bu aracı çalıştırmak için root yetkisi gereklidir.")
        exit(1)

    scan_private_networks(args.verbose)
