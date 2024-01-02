# Mengimpor modul AES dari pustaka Crypto
from Crypto.Cipher import AES

# Mengimpor fungsi get_random_bytes dari modul Crypto.Random
from Crypto.Random import get_random_bytes

# Menghasilkan kunci acak sepanjang 16 byte
key = get_random_bytes(16)

# Memasukkan data yang akan dienkripsi
data_to_encrypt = input("Masukkan teks: ")

# Mengonversi data menjadi byte dengan encoding utf-8
data = data_to_encrypt.encode('utf-8')

# Membuat objek kriptografi AES untuk enkripsi dalam mode CFB
cipher_encrypt = AES.new(key, AES.MODE_CFB)

# Melakukan enkripsi data
ciphered_bytes = cipher_encrypt.encrypt(data)

# Mendapatkan vektor inisialisasi (IV) yang digunakan dalam enkripsi
iv = cipher_encrypt.iv

# Menyimpan hasil enkripsi dan IV
ciphered_data = ciphered_bytes

# Membuat objek kriptografi AES untuk dekripsi dalam mode CFB dengan IV yang sama
cipher_decrypt = AES.new(key, AES.MODE_CFB, iv=iv)

# Melakukan dekripsi data
deciphered_bytes = cipher_decrypt.decrypt(ciphered_data)

# Mengonversi byte hasil dekripsi menjadi string dengan encoding utf-8
decrypted_data = deciphered_bytes.decode('utf-8')

# Menampilkan hasil enkripsi dan dekripsi
print("Hasil Enkripsi: ", ciphered_data)
print("Hasil Dekripsi: ", decrypted_data)
