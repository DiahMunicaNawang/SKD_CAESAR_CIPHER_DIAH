# Mengimpor modul-modul yang diperlukan dari pustaka Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii

# Generate pasangan kunci RSA dengan panjang 3000 bit
key_pair = RSA.generate(3000)

# Dapatkan kunci publik dari pasangan kunci
public_key = key_pair.publickey()
print(f"Public Key: (n={hex(public_key.n)}, e={hex(public_key.e)})")

# Ekspor kunci publik ke dalam format PEM (Privacy Enhanced Mail)
public_key_pem = public_key.exportKey()
print(public_key_pem.decode('ascii'))

# Tampilkan informasi kunci privat seperti modulus (n) dan eksponen privat (d)
print(f"Private Key: (n={hex(key_pair.n)}, d={hex(key_pair.d)})")

# Ekspor kunci privat ke dalam format PEM
private_key_pem = key_pair.exportKey()
print(private_key_pem.decode('ascii'))

# Pesan yang akan dienkripsi
message = b'Enhypen mau comeback, butuh duit nihh'

# Inisialisasi objek enkripsi dengan menggunakan kunci publik
encryptor = PKCS1_OAEP.new(public_key)
# Enkripsi pesan
encrypted = encryptor.encrypt(message)
print("Encrypted:", binascii.hexlify(encrypted))

# Inisialisasi objek dekripsi dengan menggunakan kunci privat
decryptor = PKCS1_OAEP.new(key_pair)
# Dekripsi pesan yang telah dienkripsi
decrypted = decryptor.decrypt(encrypted)
print('Decrypted:', decrypted.decode('utf-8'))
