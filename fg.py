from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# 1. Anahtar oluştur (AES-128 için 16 byte)
key = get_random_bytes(16)

# 2. Şifreleyici oluştur
cipher = AES.new(key, AES.MODE_CBC)
iv = cipher.iv  # Initialization Vector

# 3. Dosya oku
with open("ornek.txt", "rb") as file:
    data = file.read()

# 4. Veriyi şifrele
ciphertext = cipher.encrypt(pad(data, AES.block_size))

# 5. Şifreli dosyayı kaydet
with open("sifreli.dat", "wb") as file:
    file.write(iv + ciphertext)

print("Şifreleme tamamlandı. --> sifreli.dat")

# 6. Dosyayı geri aç, çöz
with open("sifreli.dat", "rb") as file:
    iv2 = file.read(16)
    ct = file.read()

cipher2 = AES.new(key, AES.MODE_CBC, iv2)
decrypted = unpad(cipher2.decrypt(ct), AES.block_size)

# 7. Geri çözülen veriyi kaydet
with open("cozuldu.txt", "wb") as file:
    file.write(decrypted)

print("Şifre çözme tamamlandı. --> cozuldu.txt")
