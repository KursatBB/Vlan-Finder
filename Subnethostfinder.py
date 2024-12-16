import subprocess
from concurrent.futures import ThreadPoolExecutor
import argparse
import os

def scan_subnet(subnet):
    """
    Bir subnet için nmap taraması yapar ve 'Nmap scan report for' sonuçlarını analiz eder.
    Aktif subnet ve host bilgilerini döndürür.
    """
    print(f"Scanning subnet: {subnet}")
    try:
        # nmap -sn komutunu çalıştır
        result = subprocess.run(["nmap", "-sn", subnet], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
        output = result.stdout

        # 'Nmap scan report for' bulunan host bilgilerini ayıkla
        hosts_info = []
        lines = output.splitlines()
        for line in lines:
            if "Nmap scan report for" in line:
                host_info = line.replace("Nmap scan report for ", "").strip()
                hosts_info.append(host_info)

        # Eğer bir subnet içinde birden fazla host varsa
        if len(hosts_info) > 1:
            return subnet, hosts_info
    except subprocess.TimeoutExpired:
        print(f"Timeout: Subnet {subnet} taranamadı.")
        return None, None
    except Exception as e:
        print(f"Error scanning subnet {subnet}: {e}")
        return None, None
    return None, None

def main():
    # Argümanları al
    parser = argparse.ArgumentParser(description="Subnet tarayıcı")
    parser.add_argument("-i", "--input_file", type=str, required=True, help="Subnetlerin bulunduğu giriş dosyası")
    parser.add_argument("-so", "--subnet_output_file", type=str, required=True, help="Aktif subnetlerin kaydedileceği dosya")
    parser.add_argument("-ho", "--hosts_output_file", type=str, required=True, help="Host bilgilerinin kaydedileceği dosya")
    parser.add_argument("-pl", "--processed_log_file", type=str, default="processed_subnets.txt", help="Taranan subnetlerin kaydedileceği dosya")
    parser.add_argument("-t", "--threads", type=int, default=2, help="Paralel çalışan thread sayısı (varsayılan: 2)")
    args = parser.parse_args()

    # Giriş dosyasını oku
    with open(args.input_file, "r") as file:
        subnets = [line.strip() for line in file if line.strip()]

    # Daha önce taranan subnetleri kontrol et
    if os.path.exists(args.processed_log_file):
        with open(args.processed_log_file, "r") as processed_file:
            processed_subnets = set(line.strip() for line in processed_file if line.strip())
    else:
        processed_subnets = set()

    # Henüz taranmamış subnetleri belirle
    subnets_to_scan = [subnet for subnet in subnets if subnet not in processed_subnets]

    # ThreadPoolExecutor ile paralel tarama
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        results = executor.map(scan_subnet, subnets_to_scan)

    # Sonuçları ayır ve dosyalara yaz
    with open(args.subnet_output_file, "a") as subnet_file, open(args.hosts_output_file, "a") as hosts_file, open(args.processed_log_file, "a") as processed_log:
        for subnet, hosts_info in results:
            if subnet and hosts_info:
                # Aktif subneti kaydet
                subnet_file.write(f"{subnet}\n")
                # İşlenen subneti loga yaz
                processed_log.write(f"{subnet}\n")

                # Host bilgilerini kaydet
                for host in hosts_info:
                    hosts_file.write(f"{host}\n")

    print(f"Tarama tamamlandı. Aktif subnetler '{args.subnet_output_file}' dosyasına, host bilgileri '{args.hosts_output_file}' dosyasına kaydedildi.")
    print(f"Taranan subnetler '{args.processed_log_file}' dosyasına kaydedildi.")

if __name__ == "__main__":
    main()