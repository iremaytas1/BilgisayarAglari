def create_dummy_pdf(filename="ornek.pdf", size_kb=500):
    with open(filename, "wb") as f:
        f.write(b"%PDF-1.4\n")  # PDF başlangıç etiketi
        f.write(b"%Test Dummy PDF\n")
        f.write(b"A" * (size_kb * 1024))  # Boyutu belirle
        f.write(b"\n%%EOF")
    print(f"{filename} adlı dosya oluşturuldu ({size_kb} KB)")

create_dummy_pdf()
