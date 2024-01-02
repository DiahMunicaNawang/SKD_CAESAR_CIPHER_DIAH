import cv2  # Import library OpenCV
import numpy as np  # Import library NumPy

def encrypt_image(image_path, output_path, key):  # Fungsi untuk mengenkripsi gambar
    # Baca gambar
    img = cv2.imread(image_path)

    # Cek apakah gambar berhasil dibaca
    if img is None:
        print("Error: Could not read the image.")  # Cetak pesan error jika gagal membaca gambar
        return

    # Generate random key based on image shape
    random_key = np.random.randint(0, 256, img.shape, dtype=np.uint8)  # Buat kunci acak

    # Enkripsi menggunakan XOR
    encrypted_img = cv2.bitwise_xor(img, random_key)  # Lakukan operasi XOR untuk mengenkripsi gambar

    # Simpan gambar terenkripsi
    cv2.imwrite(output_path, encrypted_img)  # Simpan gambar terenkripsi ke file baru

    print("Encryption complete. Encrypted image saved at", output_path)  # Cetak pesan bahwa enkripsi selesai

def decrypt_image(encrypted_path, output_path, key):
    # Baca gambar terenkripsi
    encrypted_img = cv2.imread(encrypted_path)

    # Cek apakah gambar berhasil dibaca
    if encrypted_img is None:
        print("Error: Could not read the encrypted image.")  # Cetak pesan error jika gagal membaca gambar terenkripsi
        return

    # Dekripsi menggunakan XOR dan kunci yang sama
    decrypted_img = cv2.bitwise_xor(encrypted_img, key)  # Lakukan operasi XOR untuk mendekripsi gambar

    # Simpan gambar terdekripsi
    cv2.imwrite(output_path, decrypted_img)  # Simpan gambar terdekripsi ke file baru

    print("Decryption complete. Decrypted image saved at", output_path)  # Cetak pesan bahwa dekripsi selesai

def main():  # Fungsi utama
    operation = input("Choose operation (1. encrypt or 2. decrypt): ")  # Meminta pengguna memilih operasi

    if operation == "1":  # Jika operasi adalah enkripsi
        image_path = input("Enter the path of the image to encrypt: ")  # Meminta path gambar untuk dienkripsi
        output_path = input("Enter the path to save the encrypted image: ")  # Meminta path untuk menyimpan gambar terenkripsi
        encryption_key = int(input("Enter the encryption key (an integer): "))  # Meminta kunci enkripsi

        encrypt_image(image_path, output_path, encryption_key)  # Panggil fungsi untuk mengenkripsi gambar

    elif operation == "2":  # Jika operasi adalah dekripsi
        encrypted_path = input("Enter the path of the encrypted image: ")  # Meminta path gambar terenkripsi
        output_path = input("Enter the path to save the decrypted image: ")  # Meminta path untuk menyimpan gambar terdekripsi
        encryption_key = int(input("Enter the encryption key used for decryption (an integer): "))  # Meminta kunci enkripsi yang digunakan untuk dekripsi

        decrypt_image(encrypted_path, output_path, encryption_key)  # Panggil fungsi untuk mendekripsi gambar

    else:
        print("Invalid operation. Please choose 'encrypt' or 'decrypt'.")  # Cetak pesan jika operasi tidak valid

if __name__ == "__main__":
    main()  # Jalankan fungsi utama jika skrip dijalankan sebagai program utama
