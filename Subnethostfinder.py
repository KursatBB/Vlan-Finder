import subprocess
from concurrent.futures import ThreadPoolExecutor

# Giriş ve çıkış dosyaları
input_file = "subnets.txt"  # IP'lerin olduğu dosya
output_file = "active_subnets.txt"  # Aktif subnetleri kaydedeceğimiz dosya

def scan_subnet(subnet):
    """
    Bir subnet için nmap taraması yapar ve 'Host is up' sonuçlarını kontrol eder.
    Aktif subnetleri döndürür.
    """
    try:
        # nmap -sn komutunu çalıştır
        result = subprocess.run(["nmap", "-sn", subnet], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = result.stdout
        
        # 'Host is up' sonuçlarını kontrol et
        if output.count("Host is up") > 1:  # Birden fazla aktif host varsa
            return subnet
    except Exception as e:
        print(f"Error scanning subnet {subnet}: {e}")
    return None

def main():
    # Giriş dosyasını oku
    with open(input_file, "r") as file:
        subnets = [line.strip() for line in file if line.strip()]

    # ThreadPoolExecutor ile paralel tarama
    active_subnets = []
    with ThreadPoolExecutor(max_workers=10) as executor:  # 10 thread paralel çalışır
        results = executor.map(scan_subnet, subnets)

    # Aktif subnetleri listeye ekle
    for result in results:
        if result:
            active_subnets.append(result)

    # Aktif subnetleri çıkış dosyasına yaz
    with open(output_file, "w") as file:
        file.writelines(f"{subnet}\n" for subnet in active_subnets)

    print(f"Tarama tamamlandı. Aktif subnetler '{output_file}' dosyasına kaydedildi.")

if __name__ == "__main__":
    main()
