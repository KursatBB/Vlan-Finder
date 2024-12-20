import nmap
import argparse
import subprocess
from concurrent.futures import ThreadPoolExecutor
from time import sleep
import random

# Ağ arayüzünün mevcut IP adresini alır
def get_interface_ip(interface):
    try:
        result = subprocess.run(["ifconfig", interface], stdout=subprocess.PIPE, text=True)
        output = result.stdout
        for line in output.splitlines():
            if "inet " in line and not "inet6" in line:
                ip = line.split()[1]
                return ip
        return "No IP assigned"
    except Exception as e:
        print(f"Error retrieving IP for interface {interface}: {e}")
        return "Error"

# Rastgele bir MAC adresi oluşturur
def generate_random_mac():
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0, 255) for _ in range(5))

# Ağ arayüzünü sıfırlar ve MAC adresini değiştirir
def reset_interface(interface):
    try:
        print(f"Resetting interface {interface}...")
        ip_before = get_interface_ip(interface)
        print(f"IP before reset: {ip_before}")

        subprocess.run(["sudo", "ifconfig", interface, "down"], check=True)

        # MAC adresini değiştir
        new_mac = generate_random_mac()
        subprocess.run(["sudo", "ifconfig", interface, "hw", "ether", new_mac], check=True)
        print(f"MAC address changed to: {new_mac}")

        subprocess.run(["sudo", "ifconfig", interface, "up"], check=True)

        ip_after = get_interface_ip(interface)
        print(f"IP after reset: {ip_after}")
    except Exception as e:
        print(f"Failed to reset interface {interface}: {e}")

# IP/subnet listesini bir dosyadan okur
def read_targets(file_path):
    try:
        with open(file_path, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
        return targets
    except Exception as e:
        print(f"Error reading file: {e}")
        return []

# Girilen portlara bağlı olarak çalıştırılacak scriptleri belirler
def determine_scripts(ports):
    smb_scripts = [
        "smb-enum-shares",
        "smb-enum-users",
        "smb-enum-sessions",
        "smb-os-discovery"
    ]
    rdp_scripts = [
        "rdp-enum-encryption",
        "rdp-vuln-ms12-020",
        "rdp-ntlm-info"
    ]
    additional_scripts = []

    if "139" in ports or "445" in ports:
        additional_scripts.extend(smb_scripts)
    if "3389" in ports:
        additional_scripts.extend(rdp_scripts)

    return additional_scripts

# Tek bir hedefi tarar ve Nmap sonuçlarını kaydeder
def scan_target(target, ports, scanner, output_file, scripts):
    print(f"Scanning {target} for ports {ports}...")
    try:
        script_arguments = f"--script {','.join(scripts)}" if scripts else ""
        scan_result = scanner.scan(
            hosts=target,
            ports=ports,
            arguments=f"-Pn --open {script_arguments}"
        )
        # Nmap çıktısını dosyaya kaydet
        with open(output_file, 'a') as f:
            f.write(scanner.get_nmap_output())
    except Exception as e:
        print(f"Error scanning {target}: {e}")

# Paralel tarama gerçekleştirir ve belirtilen sayıda hedef tarandıktan sonra arayüzü sıfırlar
def parallel_scan(targets, ports, output_file, max_threads, interface, hosts_limit, scripts):
    scanner = nmap.PortScanner()
    processed_hosts = 0  # İşlenen host sayacı

    def process_target(target):
        nonlocal processed_hosts
        processed_hosts += 1

        # Belirtilen host limiti aşıldığında arayüzü sıfırla
        if processed_hosts >= hosts_limit:
            reset_interface(interface)
            processed_hosts = 0

        # Hedefi tara
        scan_target(target, ports, scanner, output_file, scripts)

    # ThreadPoolExecutor kullanarak paralel tarama
    with ThreadPoolExecutor(max_threads) as executor:
        executor.map(process_target, targets)

# Ana fonksiyon
def main():
    # Komut satırı argümanlarını ayrıştırır
    parser = argparse.ArgumentParser(description="Flexible Nmap Scanner with MAC and IP Reset")
    parser.add_argument("-i", "--input", required=True, help="Path to the file containing IP/subnet list")
    parser.add_argument("-p", "--ports", required=True, help="Comma-separated list of ports to scan (e.g., 80,443,3389)")
    parser.add_argument("-o", "--output", required=True, help="Output file path to save Nmap results")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of parallel threads (default: 5)")
    parser.add_argument("-n", "--interface", required=True, help="Network interface to reset (e.g., eth0)")
    parser.add_argument("-hl", "--hosts-limit", type=int, default=10, help="Number of hosts to scan before resetting interface (default: 10)")

    args = parser.parse_args()

    # Portlara bağlı olarak scriptleri belirle
    port_list = args.ports.split(",")
    scripts = determine_scripts(port_list)

    # Hedefleri oku ve taramayı başlat
    targets = read_targets(args.input)
    parallel_scan(
        targets,
        args.ports,
        args.output,
        args.threads,
        args.interface,
        args.hosts_limit,
        scripts
    )

if __name__ == "__main__":
    main()
