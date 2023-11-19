def egcd(a, b): 
  x,y, u,v = 0,1, 1,0
  while a != 0: 
    q, r = b//a, b%a 
    m, n = x-u*q, y-v*q 
    b,a, x,y, u,v = a,r, u,v, m,n 
  gcd = b 
  return gcd, x, y 

def modinv(a, m): 
  gcd, x, y = egcd(a, m) 
  if gcd != 1: 
    return None
  else: 
    return x % m 
 
def encrypt(text, key): 
  #fungsi untuk mengenkripsi plaintext
  # E = (a*x + b) % 26 
  return ''.join([ chr((( key[0]*(ord(t) - ord('A')) + key[1] ) % 26) + ord('A')) for t in text.upper().replace(' ', '') ]) 


def decrypt(cipher, key): 
  #fungsi untuk mendekripsi chipertext
  # D(E) = (a^-1 * (E - b)) % 26
  return ''.join([ chr((( modinv(key[0], 26)*(ord(c) - ord('A') - key[1])) % 26) + ord('A')) for c in cipher ]) 


def main(): 
    print("--------------- AFFINE CHIPER ---------------")
    print("1. Encrypt")
    print("2. Decrypt")
    print("3. Exit")
    menu = input("Choose menu : ") #memilih menu


    if menu == '1': #menu enkripsi
        text = input("Enter plain text: ") #masukkan text yang akan di enkripsi
        key = [3, 5]
        enc_txt = encrypt(text,key)
        print('Plain Text : ', text)
        print('Ciphertext : ', enc_txt)
    elif menu == '2': #menu dekripsi
        text = input("Enter ciphertext: ") #masukkan text yang akan di dekripsi
        key = [3, 5]
        dec_txt = decrypt(text,key)
        print('Ciphertext : ', text)
        print('Plain Text : ', dec_txt)
    elif menu == "3": #menu keluar
        exit()
    else: #menu tidak tersedia
        print("Wrong input")



if __name__ == '__main__': 
  main() 