import socket

received = {}
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 5005))
print("[*] Alıcı dinleniyor...")

while True:
    data, addr = sock.recvfrom(2048)
    if not data:
        break
    seq = int(data[:6])
    payload = data[6:]
    received[seq] = payload
    print(f"[+] Parça {seq:06d} alındı.")

    # Basit bitiş kontrolü (paket sayısını bilmiyoruz)
    if len(payload) < 1024:
        break

# Sıralayıp dosya olarak yaz
with open("cozuldu.pdf", "wb") as f:
    for i in sorted(received.keys()):
        f.write(received[i])

print("[✓] Dosya birleştirildi: cozuldu.pdf")
sock.close()
