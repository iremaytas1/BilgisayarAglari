import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
import os
import threading
from scapy.all import sniff
from collections import defaultdict
import time

# Anahtar dosyası oluştur (ilk seferde)
if not os.path.exists("key.key"):
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    return open("key.key", "rb").read()

# Dosya Şifreleme
def encrypt_file():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return

    key = load_key()
    f = Fernet(key)

    with open(file_path, "rb") as file:
        data = file.read()

    extension = os.path.splitext(file_path)[1]
    extension_bytes = extension.encode() + b'||'

    encrypted = f.encrypt(extension_bytes + data)
    encrypted_path = file_path + ".enc"

    with open(encrypted_path, "wb") as enc_file:
        enc_file.write(encrypted)

    messagebox.showinfo("Başarılı", f"Şifrelenmiş dosya oluşturuldu:\n{encrypted_path}")

# Dosya Şifre Çözme
def decrypt_file():
    file_path = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.enc")])
    if not file_path:
        return

    key = load_key()
    f = Fernet(key)

    try:
        with open(file_path, "rb") as file:
            encrypted_data = file.read()

        decrypted = f.decrypt(encrypted_data)

        if b'||' not in decrypted:
            messagebox.showerror("Hata", "Dosya uzantısı bilgisi eksik veya bozuk.")
            return

        extension, file_content = decrypted.split(b'||', 1)
        original_path = file_path.replace(".enc", f"_cozuldu{extension.decode()}")

        with open(original_path, "wb") as dec_file:
            dec_file.write(file_content)

        messagebox.showinfo("Başarılı", f"Çözülen dosya:\n{original_path}")
    except Exception as e:
        messagebox.showerror("Hata", f"Şifre çözme başarısız:\n{str(e)}")

# IDS Modülü (ayrı thread ile çalışır)
def start_ids():
    THRESHOLD = 20
    syn_counter = defaultdict(int)
    timestamp = defaultdict(float)

    def packet_callback(packet):
        if packet.haslayer('IP') and packet.haslayer('TCP'):
            ip = packet['IP'].src
            flags = packet['TCP'].flags

            if flags == 'S':  # SYN paketi
                now = time.time()
                syn_counter[ip] += 1

                if now - timestamp[ip] > 10:
                    syn_counter[ip] = 1
                    timestamp[ip] = now

                if syn_counter[ip] > THRESHOLD:
                    log_text.insert(tk.END, f"[!] SYN Flood şüphesi: {ip} ({syn_counter[ip]} SYN)\n")
                    log_text.see(tk.END)

    sniff(filter="tcp", prn=packet_callback, store=0)

def run_ids_thread():
    ids_thread = threading.Thread(target=start_ids, daemon=True)
    ids_thread.start()

# GUI Arayüzü
root = tk.Tk()
root.title("Güvenli Dosya Aktarımı + IDS")
root.geometry("500x500")
root.configure(bg="#f0f4f7")
root.resizable(False, False)

label = tk.Label(root, text="Güvenli Dosya Aktarım Arayüzü", font=("Segoe UI", 14, "bold"), bg="#f0f4f7", fg="#333")
label.pack(pady=(20, 10))

button_encrypt = tk.Button(root, text="Dosya Seç ve Şifrele", command=encrypt_file,
                   font=("Segoe UI", 11), bg="#007acc", fg="white",
                   activebackground="#005c99", activeforeground="white", padx=10, pady=6)
button_encrypt.pack(pady=5)

button_decrypt = tk.Button(root, text="Şifreli Dosyayı Çöz", command=decrypt_file,
                   font=("Segoe UI", 11), bg="#00aa66", fg="white",
                   activebackground="#008855", activeforeground="white", padx=10, pady=6)
button_decrypt.pack(pady=5)

log_label = tk.Label(root, text="IDS Güvenlik Uyarıları:", font=("Segoe UI", 10, "bold"), bg="#f0f4f7", fg="#444")
log_label.pack(pady=(20, 5))

log_text = tk.Text(root, height=10, width=60, bg="white", fg="black", font=("Courier New", 9))
log_text.pack(padx=10, pady=5)

info = tk.Label(root, text="AES-Fernet + IDS destekli güvenli sistem", font=("Segoe UI", 9), bg="#f0f4f7", fg="#555")
info.pack(pady=10)

run_ids_thread()
root.mainloop()
