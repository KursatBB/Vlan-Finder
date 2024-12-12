from scapy.all import *
import argparse

def vlan_finder(interface, verbose):
    print("[+] VLAN Finder başlatılıyor...")

    detected_vlans = set()

    def packet_handler(packet):
        if packet.haslayer(Dot1Q):
            vlan_id = packet[Dot1Q].vlan
            if vlan_id not in detected_vlans:
                detected_vlans.add(vlan_id)
                print(f"[+] VLAN tespit edildi: VLAN ID {vlan_id}")
                if verbose:
                    print(packet.summary())

    print(f"[+] {interface} arayüzünde dinleme başlatıldı...")
    try:
        sniff(iface=interface, prn=packet_handler, filter="ether proto 0x8100", store=0)
    except KeyboardInterrupt:
        print("\n[!] Dinleme durduruldu.")
        print(f"[+] Toplam tespit edilen VLAN ID'leri: {', '.join(map(str, detected_vlans))}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VLAN Finder Tool")
    parser.add_argument("-i", "--interface", required=True, help="Dinleme yapılacak ağ arayüzü (örn. eth0)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Paket özetlerini göster")
    args = parser.parse_args()

    vlan_finder(args.interface, args.verbose)
