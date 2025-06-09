from scapy.all import *

# Paketi oluştur
pkt = IP(dst="8.8.8.8", ttl=42)/ICMP()

# Paketi göster
pkt.show()

# ÖNEMLİ: Paketi gerçekten gönder
print("Paket gönderiliyor...")
send(pkt, verbose=1)
print("Paket gönderildi!")
