import cryptography.fernet as Fernet
import os


# Definisikan lokasi file kunci
key_file = 'filekey.key'

# Jika file kunci tidak ada, buatlah kunci baru
if not os.path.exists(key_file):
    key = Fernet.Fernet.generate_key()  # Corrected line
    # Simpan kunci ke file
    with open(key_file, 'wb') as filekey:
        filekey.write(key)

# Jika file kunci ada, baca kunci dari file
else:
    with open(key_file, 'rb') as filekey:
        key = filekey.read()

# Buat objek Fernet dengan kunci
fernet = Fernet.Fernet(key)  # Corrected line

# Minta pengguna untuk memasukkan nama file yang akan dienkripsi
input_file = input("Masukkan nama file yang akan dienkripsi: ")

# Baca file yang akan dienkripsi
with open(input_file, 'rb') as file:
    original = file.read()

# Enkripsi file
encrypted = fernet.encrypt(original)

# Minta pengguna untuk memasukkan nama file baru untuk file yang telah dienkripsi
encrypted_file_name = input("Masukkan nama untuk file baru yang telah dienkripsi: ")

# Simpan file yang telah dienkripsi ke file baru
with open(encrypted_file_name, 'wb') as encrypted_file:
    encrypted_file.write(encrypted)

# Cetak pesan bahwa file telah berhasil dienkripsi
print(f'File {input_file} berhasil dienkripsi pada {encrypted_file_name}')

# Definisikan lokasi file yang telah dienkripsi
enc_file = encrypted_file_name

# Baca file yang telah dienkripsi
with open(enc_file, 'rb') as enc_file_read:
    encrypted_data = enc_file_read.read()

# Dekripsi file
decrypted = fernet.decrypt(encrypted_data)

# Minta pengguna untuk memasukkan nama file baru untuk file yang telah terdekripsi
dec_file_name = input("Masukkan nama file baru untuk file yang telah terdekripsi: ")

# Simpan file yang telah didekripsi ke file baru
with open(dec_file_name, 'wb') as dec_file:
    dec_file.write(decrypted)

# Cetak pesan bahwa file telah berhasil didekripsi
print(f'File {encrypted_file_name} berhasil didekripsi pada {dec_file_name}')
