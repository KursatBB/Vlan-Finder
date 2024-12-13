import os
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import subprocess
from scapy.all import *

def is_host_alive(ip):
    try:
        result = subprocess.run(["ping", "-c", "1", "-W", "0.2", str(ip)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            return ip
    except Exception as e:
        pass
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

def detect_vlan(ip):
    try:
        response = srp1(Ether(dst="ff:ff:ff:ff:ff:ff") / Dot1Q(vlan=1) / ARP(pdst=str(ip)), timeout=0.5, verbose=False)
        if response and response.haslayer(Dot1Q):
            return response[Dot1Q].vlan
    except Exception as e:
        pass
    return None

def scan_private_networks(output_file, vlan_output_file, verbose):
    print("[+] Tüm yerel IP adresleri taranıyor...")
    networks = generate_all_private_networks()
    active_hosts = []
    detected_vlans = {}

    with ThreadPoolExecutor(max_workers=500) as executor:
        futures = []
        for network in networks:
            net = ipaddress.ip_network(network, strict=False)
            print(f"[+] Tarama başlatıldı: {network}")
            previous_subnet = None
            for ip in net.hosts():
                current_subnet = ipaddress.ip_network(f"{ip}/24", strict=False)
                if previous_subnet != current_subnet:
                    print(f"[+] Yeni ağ taranıyor: {current_subnet}")
                    previous_subnet = current_subnet
                futures.append(executor.submit(is_host_alive, ip))

        for future in as_completed(futures):
            result = future.result()
            if result:
                active_hosts.append(result)
                print(f"[+] {result} üzerinde VLAN taraması yapılıyor...")
                vlan_id = detect_vlan(result)
                if vlan_id:
                    detected_vlans[result] = vlan_id

    print("\n[+] Tarama tamamlandı.")
    print(f"[+] Aktif IP'ler dosyaya yazılıyor: {output_file}")
    with open(output_file, "w") as f:
        for host in active_hosts:
            f.write(f"{host}\n")

    print(f"[+] Tespit edilen VLAN'lar dosyaya yazılıyor: {vlan_output_file}")
    with open(vlan_output_file, "w") as f:
        for host, vlan in detected_vlans.items():
            f.write(f"{host} - VLAN ID: {vlan}\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Tüm Yerel IP Adreslerini ve VLAN'ları Tarama Aracı")
    parser.add_argument("-o", "--output", required=True, help="Aktif IP'lerin kaydedileceği dosya yolu")
    parser.add_argument("-vlan", "--vlan-output", required=True, help="Tespit edilen VLAN'ların kaydedileceği dosya yolu")
    parser.add_argument("-v", "--verbose", action="store_true", help="Detaylı çıktı göster")
    args = parser.parse_args()

    # Kontrol için root yetkisi gerekliliği
    if os.geteuid() != 0:
        print("[!] Bu aracı çalıştırmak için root yetkisi gereklidir.")
        exit(1)

    scan_private_networks(args.output, args.vlan_output, args.verbose)
