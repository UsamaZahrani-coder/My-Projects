def caesar_cipher_encrypt(text, shift):
    """
    Encrypts a text using the Caesar cipher.

    Args:
        text (str): The input text to be encrypted.
        shift (int): The shift value for the cipher.

    Returns:
        str: The resulting encrypted text.
    """
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            shifted_char = chr((ord(char) - 65 + shift) % 26 + 65) if char.isupper() else chr((ord(char) - 97 + shift) % 26 + 97)
            encrypted_text += shifted_char
        else:
            encrypted_text += char
    return encrypted_text

def caesar_cipher_decrypt(text, shift):
    """
    Decrypts a text using the Caesar cipher.

    Args:
        text (str): The input text to be decrypted.
        shift (int): The shift value for the cipher.

    Returns:
        str: The resulting decrypted text.
    """
    return caesar_cipher_encrypt(text, -shift)

def main():
    print("Welcome to the Caesar Cipher program!")
    message = input("Enter the message to encrypt: ")
    shift = int(input("Enter the shift value for encryption (positive for encryption, negative for decryption): "))

    encrypted_message = caesar_cipher_encrypt(message, shift)
    print("Encrypted text:", encrypted_message)

    decrypted_message = caesar_cipher_decrypt(encrypted_message, shift)
    print("Decrypted text:", decrypted_message)

if __name__ == "__main__":
    main()
