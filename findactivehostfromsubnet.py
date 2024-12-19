import os
import subprocess
import tempfile
import re
import argparse

def find_active_hosts(subnet):
    # "nmap -sn" komutunu çalıştır
    print(f"[*] Aktif hostları tarıyor: {subnet}")
    result = subprocess.run(["nmap", "-sn", subnet], capture_output=True, text=True)
    
    # Çıktıdan aktif hostları bul
    active_hosts = []
    for line in result.stdout.splitlines():
        if "Nmap scan report" in line:
            # IP adresini hostname ile veya direkt formatta bul
            match = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", line)  # Parantez içindeki IP'yi al
            if match:
                ip = match.group(1)
            else:
                ip = line.split()[-1]  # Parantez yoksa son sütunu al
            active_hosts.append(ip)
    
    print(f"[+] Aktif hostlar bulundu: {active_hosts}")
    return active_hosts

def detailed_scan(active_hosts, subnet_name):
    # Geçici bir dosya oluştur ve IP'leri yaz
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as temp_file:
        temp_file_path = temp_file.name
        for ip in active_hosts:
            temp_file.write(ip + "\n")
    
    # "nmap -iL" ile detaylı tarama yap
    output_file = f"{subnet_name}.txt"
    print(f"[*] Detaylı tarama başlatılıyor, sonuç dosyası: {output_file}")
    subprocess.run(["nmap", "-iL", temp_file_path, "-sC", "-sV", "-O", "-oN", output_file])
    
    # Geçici dosyayı sil
    os.remove(temp_file_path)
    print(f"[+] Tarama tamamlandı. Sonuçlar: {output_file}")

def main():
    # Argparse ile parametreleri al
    parser = argparse.ArgumentParser(description="Subnet için nmap taraması yapar.")
    parser.add_argument("subnet", help="Tarama yapılacak subnet (örnek: 192.168.1.0/24)")
    args = parser.parse_args()

    subnet = args.subnet
    subnet_name = subnet.replace("/", "_").replace(".", "_")

    # Aktif hostları bul
    active_hosts = find_active_hosts(subnet)
    
    if active_hosts:
        # Detaylı tarama yap
        detailed_scan(active_hosts, subnet_name)
    else:
        print("[-] Aktif host bulunamadı, işlem sonlandırılıyor.")

if __name__ == "__main__":
    main()
