import ipaddress
from collections import defaultdict
import argparse

def group_hosts_by_subnet(hosts_file, output_file, min_hosts=2):
    """
    Hostları subnetlere gruplar ve sadece en az belirli sayıda host içeren subnetleri kaydeder.
    """
    # Subnetlere göre hostları gruplamak için defaultdict kullan
    subnet_groups = defaultdict(list)

    # Hostları oku ve subnetlere grupla
    with open(hosts_file, "r") as file:
        for line in file:
            host = line.strip()
            if host:
                try:
                    # /24 subnetine göre gruplama yap
                    subnet = str(ipaddress.ip_network(f"{host}/24", strict=False))
                    subnet_groups[subnet].append(host)
                except ValueError:
                    print(f"[!] Geçersiz IP adresi atlandı: {host}")

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
