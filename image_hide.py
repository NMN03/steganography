import argparse
import sys
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

def encrypt_data(data, public_key):
    # Generate a random session key
    session_key = os.urandom(32)  # 32 bytes for 256-bit key
    
    # Derive a symmetric key from the session key
    salt = os.urandom(16)  # 16 bytes for 128-bit salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,  # Increased iterations for added security
        backend=default_backend()
    )
    key = kdf.derive(session_key)
    
    # Encrypt the data with AES
    iv = os.urandom(16)  # 16 bytes for 128-bit IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # Encrypt the session key with RSA
    encrypted_session_key = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return encrypted_session_key, salt, iv, encrypted_data

def hide_image_in_png(image_path, image_to_hide_path, output_image_path, public_key_path):
    # Load the public key
    with open(public_key_path, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    # Load the image to be hidden
    hidden_image = Image.open(image_to_hide_path)

    # Convert the image to bytes
    hidden_image_bytes = hidden_image.tobytes()

    # Read the original image
    img = Image.open(image_path)

    # Convert to RGBA if not already in that format
    if img.mode != 'RGBA':
        img = img.convert('RGBA')

    # This will give you the original format of the image
    host_format = img.format

    pixels = np.array(img)

    # Get the dimensions of the hidden image
    hidden_width, hidden_height = hidden_image.size

    # Check if the host image is large enough to hide the hidden image
    if hidden_width * hidden_height * 3 > pixels.size // 4:  # Multiply by 3 for RGB channels
        raise ValueError("Host image is not large enough to hide the hidden image.")

    # Embed the hidden image bytes into the host image using LSB method
    pixel_indices = list(range(pixels.size // 4))
    random.shuffle(pixel_indices)  # Shuffle using a random generator

    for i, byte in enumerate(hidden_image_bytes):
        for bit in range(8):
            idx = pixel_indices[i * 8 + bit]
            # Encode each bit of the hidden image byte into the least significant bit of the host image pixel
            pixels[idx // pixels.shape[1], idx % pixels.shape[1], i % 3] = \
                (pixels[idx // pixels.shape[1], idx % pixels.shape[1], i % 3] & ~0x1) | ((byte >> (7 - bit)) & 0x1)

    # Save the new image
    new_img = Image.fromarray(pixels, 'RGBA')
    new_img.save(output_image_path, format=host_format, optimize=True)

    print(f"Image '{image_to_hide_path}' has been successfully hidden in '{output_image_path}'.")

def main():
    parser = argparse.ArgumentParser(description='Hide an image inside another image')
    parser.add_argument('host', type=str, help='Path to the host image')
    parser.add_argument('secret', type=str, help='Path to the image to hide')
    parser.add_argument('pubkey', type=str, help='Path to the public key for encryption')
    parser.add_argument('output', type=str, help='Path to the output image with embedded data')
    args = parser.parse_args()

    hide_image_in_png(args.host, args.secret, args.output, args.pubkey)

if __name__ == '__main__':
    main()
