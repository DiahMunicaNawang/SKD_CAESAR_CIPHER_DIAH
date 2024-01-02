from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii


key_pair = RSA.generate(3000)

public_key = key_pair.publickey()
print(f"Public Key: (n={hex(public_key.n)}, e={hex(public_key.e)})")
public_key_pem = public_key.exportKey()
print(public_key_pem.decode('ascii'))

print(f"Private Key: (n={hex(key_pair.n)}, d={hex(key_pair.d)})")
private_key_pem = key_pair.exportKey()
print(private_key_pem.decode('ascii'))

message = b'Enhypen mau comeback, butuh duit nihh'


encryptor = PKCS1_OAEP.new(public_key)
encrypted = encryptor.encrypt(message)
print("Encrypted:", binascii.hexlify(encrypted))

decryptor = PKCS1_OAEP.new(key_pair)
decrypted = decryptor.decrypt(encrypted)
print('Decrypted:', decrypted.decode('utf-8'))
