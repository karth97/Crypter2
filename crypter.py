#!/usr/bin/python3
"""
Go-Style File Crypter in Python
by Karhteek Chanda
"""

import sys
import os
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import hashlib

class FileCrypter:
    def __init__(self, key=None):
        """Initialize with existing key or generate new"""
        if key:
            if len(key) != 32:
                raise ValueError("Key must be 32 bytes (256-bit)")
            self.key = key
        else:
            self.key = secrets.token_bytes(32)
        
        self.chunk_size = 65536  # 64KB chunks
    
    def encrypt_file(self, input_path, output_path):
        """Encrypt file using AES-CBC with random IV"""
        # Generate random IV
        iv = secrets.token_bytes(16)
        
        # Read input file
        file_size = os.path.getsize(input_path)
        
        # Setup AES-CBC cipher
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        
        with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
            # Write IV first
            outfile.write(iv)
            
            # Encrypt in chunks
            while True:
                chunk = infile.read(self.chunk_size)
                if not chunk:
                    break
                
                # Pad the last chunk
                if len(chunk) < self.chunk_size:
                    chunk = padder.update(chunk) + padder.finalize()
                
                encrypted = encryptor.update(chunk)
                outfile.write(encrypted)
            
            # Finalize encryption
            outfile.write(encryptor.finalize())
        
        return True
    
    def get_key_hex(self):
        """Return key as hex string"""
        return self.key.hex()
    
    def save_key(self, key_path):
        """Save key to file"""
        with open(key_path, 'w') as f:
            f.write(self.key.hex())
        return key_path

def main():
    if len(sys.argv) < 3:
        print("🔐 Python File Crypter - Educational Use Only")
        print("=" * 50)
        print("Usage: python3 crypter.py <input.exe> <output.enc>")
        print("Example: python3 crypter.py payload.exe encrypted.bin")
        print("\nAdditional options:")
        print("  --key <HEX_KEY>    Use specific key")
        print("  --test             Test with sample file")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    # Check if using custom key
    if len(sys.argv) > 3 and sys.argv[3] == "--key":
        key_hex = sys.argv[4]
        key = bytes.fromhex(key_hex)
        crypter = FileCrypter(key)
    else:
        crypter = FileCrypter()
    
    print(f"🔒 Encrypting: {input_file} → {output_file}")
    
    try:
        # Encrypt the file
        crypter.encrypt_file(input_file, output_file)
        
        # Save key
        key_file = output_file + ".key"
        crypter.save_key(key_file)
        
        # Get file stats
        input_size = os.path.getsize(input_file)
        output_size = os.path.getsize(output_file)
        
        print("\n✅ Encryption Successful!")
        print("=" * 40)
        print(f"Input file:  {input_file}")
        print(f"Output file: {output_file}")
        print(f"Key file:    {key_file}")
        print(f"Key:         {crypter.get_key_hex()}")
        print(f"\nFile sizes:")
        print(f"  Original:  {input_size:,} bytes")
        print(f"  Encrypted: {output_size:,} bytes (+16 byte IV)")
        print(f"  Overhead:  {output_size - input_size} bytes")
        
        # Show hash comparison
        print(f"\nSHA256 Hashes:")
        with open(input_file, 'rb') as f:
            orig_hash = hashlib.sha256(f.read()).hexdigest()
        with open(output_file, 'rb') as f:
            enc_hash = hashlib.sha256(f.read()).hexdigest()
        
        print(f"  Original:  {orig_hash[:16]}...")
        print(f"  Encrypted: {enc_hash[:16]}...")
        print(f"\n⚠️  Keep the key file safe! It's required for decryption.")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

def test_crypter():
    """Test the crypter with a sample file"""
    print("🧪 Testing crypter...")
    
    # Create test file
    test_data = b"MZ" + os.urandom(1024)  # Fake PE header
    with open("test_sample.exe", "wb") as f:
        f.write(test_data)
    
    # Create crypter instance
    crypter = FileCrypter()
    
    # Encrypt
    crypter.encrypt_file("test_sample.exe", "test_encrypted.bin")
    crypter.save_key("test_key.txt")
    
    # Show results
    print(f"Test file created: test_sample.exe")
    print(f"Encrypted to: test_encrypted.bin")
    print(f"Test key: {crypter.get_key_hex()[:16]}...")
    
    # Cleanup
    os.remove("test_sample.exe")
    print("Test complete. Files remain for inspection.")

if __name__ == "__main__":
    # Check for test mode
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        test_crypter()
    else:
        main()
