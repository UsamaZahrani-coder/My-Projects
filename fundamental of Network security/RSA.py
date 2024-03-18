from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

def generate_rsa_key_pair():
    # Generate an RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key, private_key.public_key()

def rsa_encrypt(message, public_key):
    # Serialize the public key
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Load the public key
    loaded_public_key = serialization.load_pem_public_key(pem, backend=default_backend())

    # Encrypt the message
    ciphertext = loaded_public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def rsa_decrypt(ciphertext, private_key):
    # Decrypt the ciphertext
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()

def main():
    # Generate an RSA key pair
    private_key, public_key = generate_rsa_key_pair()

    # User input for message
    message = input("Enter the message to encrypt: ")

    # Encrypt the message
    encrypted_message = rsa_encrypt(message, public_key)
    print("Encrypted message:", encrypted_message.hex())

    # Decrypt the encrypted message
    decrypted_message = rsa_decrypt(encrypted_message, private_key)
    print("Decrypted message:", decrypted_message)

if __name__ == "__main__":
    main()
