from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encrypt(plaintext, key):
    # Gerando um nonce de 12 bytes
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    # Tag é a marca de autenticação que será usada para verificar autencidade dos dados no processo de descriptografia.
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
    return ciphertext, tag, nonce

def decrypt(ciphertext, tag, nonce, key):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted_text = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted_text.decode('utf-8')

# Gera uma chave AES de 256 bits
key = get_random_bytes(32)
plaintext = "CESAR School"

ciphertext, tag, nonce = encrypt(plaintext, key)
print('Encoding...')
print(f'Ciphertext: {ciphertext.hex()} | Tag: {tag.hex()} | Nonce: {nonce.hex()}')

print('Decoding...')
decrypted_text = decrypt(ciphertext, tag, nonce, key)
print(f'Decrypted Text: {decrypted_text}')