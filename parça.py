import socket
import sys

# Kullanım kontrolü
if len(sys.argv) != 2:
    print("Kullanım: python parça.py <dosya_adı>")
    sys.exit(1)

filename = sys.argv[1]

# Dosyayı oku
with open(filename, "rb") as f:
    data = f.read()

# Parçalama
chunks = [data[i:i+1024] for i in range(0, len(data), 1024)]

# UDP soketi
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
receiver_ip = "127.0.0.1"  # Alıcının IP adresi (yerel test için)
receiver_port = 5005       # Alıcı portu

# Gönderim
for idx, chunk in enumerate(chunks):
    packet = f"{idx:06d}".encode() + chunk
    sock.sendto(packet, (receiver_ip, receiver_port))
    print(f"[+] Parça {idx:06d} gönderildi.")

print("[✓] Gönderim tamamlandı.")
sock.close()
