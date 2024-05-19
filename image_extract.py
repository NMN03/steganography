import argparse
import os
import random
from PIL import Image
import numpy as np
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from getpass import getpass

def decrypt_data(encrypted_session_key, salt, iv, encrypted_data, private_key):
    # Decrypt the session key with RSA
    session_key = private_key.decrypt(
        encrypted_session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Derive the symmetric key from the session key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,  # Increased iterations for added security
        backend=default_backend()
    )
    key = kdf.derive(session_key)
    
    # Decrypt the data with AES
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    
    return decrypted_data

def extract_image_from_png(image_path, output_image_path, private_key_path):
    # Load the private key
    passphrase = getpass("Enter the private key passphrase: ")
    with open(private_key_path, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=passphrase.encode(),
            backend=default_backend()
        )

    # Read the steganographed image
    img = Image.open(image_path)
    if img.mode not in ['RGB', 'RGBA']:
        raise ValueError("Image must be in RGB or RGBA format.")

    # Convert to RGBA if not already in that format
    if img.mode != 'RGBA':
        img = img.convert('RGBA')

    pixels = np.array(img)

    # Get the dimensions of the hidden image
    hidden_width, hidden_height = img.size

    # Prepare a list to store the extracted bytes
    extracted_bytes = bytearray()

    # Generate a list of unique indices to extract the data
    pixel_indices = list(range(pixels.size // 4))
    random.shuffle(pixel_indices)  # Shuffle using a random generator

    # Extract the hidden image bytes using LSB method
    for i in range(hidden_width * hidden_height * 3):
        idx = pixel_indices[i]
        # Extract the least significant bit of each channel of the pixel
        extracted_bytes.append(pixels[idx // pixels.shape[1], idx % pixels.shape[1], i % 3] & 0x1)

    # Convert the extracted bytes to a byte array
    data_to_decode = bytes(extracted_bytes)

    # Reconstruct the hidden image from the extracted bytes
    extracted_image = Image.frombytes('RGB', (hidden_width, hidden_height), data_to_decode)

    # Save the extracted image
    extracted_image.save(output_image_path)

    print(f"Image extracted to {output_image_path}")

def main():
    parser = argparse.ArgumentParser(description='Extract an image from another image')
    parser.add_argument('carrier', type=str, help='Path to the carrier image with embedded data')
    parser.add_argument('privkey', type=str, help='Path to the private key for decryption')
    parser.add_argument('extracted', nargs='?', type=str, default=None, help='Path to save the extracted image (optional, defaults to "extracted.png")')
    args = parser.parse_args()

    # If no output image path is provided, use None to trigger default behavior
    output_image_path = args.extracted if args.extracted else 'extracted.png'
    extract_image_from_png(args.carrier, output_image_path, args.privkey)

if __name__ == '__main__':
    main()
