# Metin dosyasını okuyup açık portlara sahip IP adreslerini bulmak
open_ports = []

with open("nmap_output.txt", "r") as file:  # Dosyanızın adı nmap_output.txt olabilir
    lines = file.readlines()

for i, line in enumerate(lines):
    if "445/tcp open" in line:  # "445/tcp open" geçen satırları bul
        # Bir önceki satırda IP adresi bulunuyor
        if i > 0 and "Nmap scan report for" in lines[i-1]:
            ip_address = lines[i-1].strip().split()[-1]  # IP adresini al
            open_ports.append(ip_address)

# Bulunan IP adreslerini yazdır
print("Açık porta sahip IP adresleri:")
for ip in open_ports:
    print(ip)

# Eğer sonuçları bir dosyaya kaydetmek isterseniz
with open("open_ports_ips.txt", "w") as output_file:
    for ip in open_ports:
        output_file.write(ip + "\n")
