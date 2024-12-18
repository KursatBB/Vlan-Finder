import ipaddress
from collections import defaultdict
import argparse
import re

def extract_ip_from_hostname(host):
    """
    Hostname içinde bir IP adresi varsa ayıklar. Örnek: 'hostname.local (192.168.1.1)' -> '192.168.1.1'
    """
    match = re.search(r"\(([\d\.]+)\)", host)
    return match.group(1) if match else None

def group_hosts_by_subnet(hosts_file, output_file, min_hosts=2):
    """
    Hostları subnetlere gruplar ve sadece en az belirli sayıda host içeren subnetleri kaydeder.
    """
    subnet_groups = defaultdict(list)

    # Hostları oku ve subnetlere grupla
    with open(hosts_file, "r") as file:
        for line in file:
            host = line.strip()
            if host:
                # IP adresini hostname'den ayıkla
                ip = extract_ip_from_hostname(host) or host
                try:
                    # IP adresinden subneti oluştur
                    subnet = str(ipaddress.ip_network(f"{ip}/24", strict=False))
                    subnet_groups[subnet].append(host)  # Orijinal hostu ekle (IP veya hostname)
                except ValueError:
                    print(f"[!] Geçersiz IP veya hostname atlandı: {host}")

    # En az `min_hosts` sayıda host içeren subnetleri filtrele
    filtered_subnets = {subnet: hosts for subnet, hosts in subnet_groups.items() if len(hosts) >= min_hosts}

    # Sonuçları dosyaya yaz
    with open(output_file, "w") as file:
        for subnet, hosts in filtered_subnets.items():
            file.write(f"Subnet: {subnet}\n")
            for host in hosts:
                file.write(f"  {host}\n")
            file.write("\n")

    print(f"[+] Subnetler '{output_file}' dosyasına kaydedildi.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Hostlardan Subnet Çıkartma Aracı")
    parser.add_argument("-i", "--input", required=True, help="Hostların bulunduğu giriş dosyası")
    parser.add_argument("-o", "--output", required=True, help="Çıktının kaydedileceği dosya")
    parser.add_argument("-m", "--min-hosts", type=int, default=2, help="Bir subnette olması gereken minimum host sayısı (varsayılan: 2)")
    args = parser.parse_args()

    group_hosts_by_subnet(args.input, args.output, args.min_hosts)
