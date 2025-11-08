"""
Cryptography Lab - Symmetric & Asymmetric Encryption Program
Author: Lab 4 Solution
Date: November 8, 2025

Online Resources Used:
1. Cryptography library documentation: https://cryptography.io/en/latest/
2. PyCryptodome documentation: https://pycryptodome.readthedocs.io/en/latest/
3. Python hashlib documentation: https://docs.python.org/3/library/hashlib.html
4. RSA encryption tutorial: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
5. AES encryption examples: https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/

This program implements:
- AES encryption/decryption (128-bit and 256-bit keys, ECB and CFB modes)
- RSA encryption/decryption
- RSA digital signatures
- SHA-256 hashing
- Execution time measurement
"""

import os
import time
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import utils


class CryptoLab:
    def __init__(self):
        self.keys_dir = "keys"
        self.output_dir = "output"
        self._create_directories()
        
    def _create_directories(self):
        """Create necessary directories for keys and output"""
        if not os.path.exists(self.keys_dir):
            os.makedirs(self.keys_dir)
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
    
    def _pad_data(self, data, block_size=16):
        """Add PKCS7 padding to data for block cipher"""
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    def _unpad_data(self, data):
        """Remove PKCS7 padding from data"""
        padding_length = data[-1]
        return data[:-padding_length]
    
    # ==================== AES OPERATIONS ====================
    
    def generate_aes_key(self, key_size):
        """Generate AES key and save to file
        Args:
            key_size: 128 or 256 bits
        """
        key = os.urandom(key_size // 8)
        key_file = os.path.join(self.keys_dir, f"aes_{key_size}_key.bin")
        with open(key_file, 'wb') as f:
            f.write(key)
        print(f"AES-{key_size} key generated and saved to {key_file}")
        return key
    
    def load_aes_key(self, key_size):
        """Load AES key from file"""
        key_file = os.path.join(self.keys_dir, f"aes_{key_size}_key.bin")
        if not os.path.exists(key_file):
            print(f"Key file not found. Generating new key...")
            return self.generate_aes_key(key_size)
        with open(key_file, 'rb') as f:
            return f.read()
    
    def aes_encrypt(self, plaintext, key_size=128, mode='ECB'):
        """Encrypt data using AES
        Args:
            plaintext: String to encrypt
            key_size: 128 or 256 bits
            mode: 'ECB' or 'CFB'
        Returns:
            execution_time: Time taken for encryption
        """
        start_time = time.time()
        
        key = self.load_aes_key(key_size)
        plaintext_bytes = plaintext.encode('utf-8')
        
        if mode == 'ECB':
            # ECB mode
            plaintext_bytes = self._pad_data(plaintext_bytes)
            cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()
            
            # Save encrypted data
            output_file = os.path.join(self.output_dir, f"aes_{key_size}_ecb_encrypted.bin")
            with open(output_file, 'wb') as f:
                f.write(ciphertext)
                
        elif mode == 'CFB':
            # CFB mode - requires IV
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()
            
            # Save IV + encrypted data
            output_file = os.path.join(self.output_dir, f"aes_{key_size}_cfb_encrypted.bin")
            with open(output_file, 'wb') as f:
                f.write(iv + ciphertext)
        else:
            raise ValueError("Mode must be 'ECB' or 'CFB'")
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        print(f"Encryption successful using AES-{key_size} {mode} mode")
        print(f"Encrypted data saved to: {output_file}")
        print(f"Execution time: {execution_time:.6f} seconds")
        
        return execution_time
    
    def aes_decrypt(self, key_size=128, mode='ECB'):
        """Decrypt data using AES
        Args:
            key_size: 128 or 256 bits
            mode: 'ECB' or 'CFB'
        Returns:
            execution_time: Time taken for decryption
        """
        start_time = time.time()
        
        key = self.load_aes_key(key_size)
        
        if mode == 'ECB':
            input_file = os.path.join(self.output_dir, f"aes_{key_size}_ecb_encrypted.bin")
            with open(input_file, 'rb') as f:
                ciphertext = f.read()
            
            cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()
            plaintext = self._unpad_data(plaintext_padded)
            
        elif mode == 'CFB':
            input_file = os.path.join(self.output_dir, f"aes_{key_size}_cfb_encrypted.bin")
            with open(input_file, 'rb') as f:
                data = f.read()
            
            iv = data[:16]
            ciphertext = data[16:]
            
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        else:
            raise ValueError("Mode must be 'ECB' or 'CFB'")
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        print(f"Decryption successful using AES-{key_size} {mode} mode")
        print(f"Decrypted text: {plaintext.decode('utf-8')}")
        print(f"Execution time: {execution_time:.6f} seconds")
        
        return execution_time
    
    # ==================== RSA OPERATIONS ====================
    
    def generate_rsa_keys(self, key_size=2048):
        """Generate RSA key pair and save to files
        Args:
            key_size: Key size in bits (e.g., 1024, 2048, 4096)
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        # Save private key
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        private_key_file = os.path.join(self.keys_dir, f"rsa_{key_size}_private.pem")
        with open(private_key_file, 'wb') as f:
            f.write(private_pem)
        
        # Save public key
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_key_file = os.path.join(self.keys_dir, f"rsa_{key_size}_public.pem")
        with open(public_key_file, 'wb') as f:
            f.write(public_pem)
        
        print(f"RSA-{key_size} key pair generated")
        print(f"Private key saved to: {private_key_file}")
        print(f"Public key saved to: {public_key_file}")
    
    def load_rsa_keys(self, key_size=2048):
        """Load RSA key pair from files"""
        private_key_file = os.path.join(self.keys_dir, f"rsa_{key_size}_private.pem")
        public_key_file = os.path.join(self.keys_dir, f"rsa_{key_size}_public.pem")
        
        if not os.path.exists(private_key_file) or not os.path.exists(public_key_file):
            print(f"RSA-{key_size} keys not found. Generating new keys...")
            self.generate_rsa_keys(key_size)
        
        with open(private_key_file, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        
        with open(public_key_file, 'rb') as f:
            public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
        
        return private_key, public_key
    
    def rsa_encrypt(self, plaintext, key_size=2048):
        """Encrypt data using RSA public key
        Args:
            plaintext: String to encrypt
            key_size: RSA key size in bits
        Returns:
            execution_time: Time taken for encryption
        """
        start_time = time.time()
        
        _, public_key = self.load_rsa_keys(key_size)
        plaintext_bytes = plaintext.encode('utf-8')
        
        ciphertext = public_key.encrypt(
            plaintext_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        output_file = os.path.join(self.output_dir, f"rsa_{key_size}_encrypted.bin")
        with open(output_file, 'wb') as f:
            f.write(ciphertext)
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        print(f"RSA-{key_size} encryption successful")
        print(f"Encrypted data saved to: {output_file}")
        print(f"Execution time: {execution_time:.6f} seconds")
        
        return execution_time
    
    def rsa_decrypt(self, key_size=2048):
        """Decrypt data using RSA private key
        Args:
            key_size: RSA key size in bits
        Returns:
            execution_time: Time taken for decryption
        """
        start_time = time.time()
        
        private_key, _ = self.load_rsa_keys(key_size)
        
        input_file = os.path.join(self.output_dir, f"rsa_{key_size}_encrypted.bin")
        with open(input_file, 'rb') as f:
            ciphertext = f.read()
        
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        print(f"RSA-{key_size} decryption successful")
        print(f"Decrypted text: {plaintext.decode('utf-8')}")
        print(f"Execution time: {execution_time:.6f} seconds")
        
        return execution_time
    
    # ==================== RSA SIGNATURE OPERATIONS ====================
    
    def rsa_sign(self, file_path, key_size=2048):
        """Generate RSA signature for a file
        Args:
            file_path: Path to the file to sign
            key_size: RSA key size in bits
        Returns:
            execution_time: Time taken for signing
        """
        start_time = time.time()
        
        private_key, _ = self.load_rsa_keys(key_size)
        
        # Read file content
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Sign the data
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Save signature
        signature_file = os.path.join(self.output_dir, f"rsa_{key_size}_signature.bin")
        with open(signature_file, 'wb') as f:
            f.write(signature)
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        print(f"RSA-{key_size} signature generated successfully")
        print(f"Signature saved to: {signature_file}")
        print(f"Execution time: {execution_time:.6f} seconds")
        
        return execution_time
    
    def rsa_verify(self, file_path, signature_file, key_size=2048):
        """Verify RSA signature
        Args:
            file_path: Path to the original file
            signature_file: Path to the signature file
            key_size: RSA key size in bits
        Returns:
            execution_time: Time taken for verification
        """
        start_time = time.time()
        
        _, public_key = self.load_rsa_keys(key_size)
        
        # Read file content
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Read signature
        with open(signature_file, 'rb') as f:
            signature = f.read()
        
        # Verify signature
        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            verification_result = True
            print("Signature verification: SUCCESSFUL")
        except Exception as e:
            verification_result = False
            print(f"Signature verification: FAILED - {str(e)}")
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        print(f"Execution time: {execution_time:.6f} seconds")
        
        return execution_time
    
    # ==================== SHA-256 HASHING ====================
    
    def sha256_hash(self, file_path):
        """Generate SHA-256 hash of a file
        Args:
            file_path: Path to the file to hash
        Returns:
            execution_time: Time taken for hashing
        """
        start_time = time.time()
        
        sha256 = hashlib.sha256()
        
        # Read and hash file in chunks for efficiency
        with open(file_path, 'rb') as f:
            while True:
                data = f.read(65536)  # Read in 64KB chunks
                if not data:
                    break
                sha256.update(data)
        
        hash_value = sha256.hexdigest()
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        print(f"SHA-256 hash of {file_path}:")
        print(f"Hash: {hash_value}")
        print(f"Execution time: {execution_time:.6f} seconds")
        
        return execution_time
    
    # ==================== PERFORMANCE TESTING ====================
    
    def performance_test_aes(self):
        """Test AES performance with different key sizes"""
        print("\n" + "="*60)
        print("AES PERFORMANCE TEST")
        print("="*60)
        
        test_data = "This is a test message for performance measurement." * 100
        key_sizes = [128, 256]
        modes = ['ECB', 'CFB']
        
        results = []
        
        for key_size in key_sizes:
            for mode in modes:
                print(f"\nTesting AES-{key_size} {mode} mode...")
                
                # Encryption
                enc_time = self.aes_encrypt(test_data, key_size, mode)
                
                # Decryption
                dec_time = self.aes_decrypt(key_size, mode)
                
                results.append({
                    'algorithm': f'AES-{key_size}-{mode}',
                    'key_size': key_size,
                    'mode': mode,
                    'encryption_time': enc_time,
                    'decryption_time': dec_time
                })
        
        # Save results to file
        results_file = os.path.join(self.output_dir, "aes_performance_results.txt")
        with open(results_file, 'w') as f:
            f.write("AES Performance Test Results\n")
            f.write("="*60 + "\n")
            for r in results:
                f.write(f"\nAlgorithm: {r['algorithm']}\n")
                f.write(f"Key Size: {r['key_size']} bits\n")
                f.write(f"Mode: {r['mode']}\n")
                f.write(f"Encryption Time: {r['encryption_time']:.6f} seconds\n")
                f.write(f"Decryption Time: {r['decryption_time']:.6f} seconds\n")
        
        print(f"\nResults saved to: {results_file}")
        return results
    
    def performance_test_rsa(self):
        """Test RSA performance with different key sizes"""
        print("\n" + "="*60)
        print("RSA PERFORMANCE TEST")
        print("="*60)
        
        test_data = "This is a test message for RSA performance measurement."
        key_sizes = [1024, 2048, 3072, 4096]
        
        results = []
        
        for key_size in key_sizes:
            print(f"\nTesting RSA-{key_size}...")
            
            # Generate keys
            self.generate_rsa_keys(key_size)
            
            # Encryption
            enc_time = self.rsa_encrypt(test_data, key_size)
            
            # Decryption
            dec_time = self.rsa_decrypt(key_size)
            
            results.append({
                'key_size': key_size,
                'encryption_time': enc_time,
                'decryption_time': dec_time
            })
        
        # Save results to file
        results_file = os.path.join(self.output_dir, "rsa_performance_results.txt")
        with open(results_file, 'w') as f:
            f.write("RSA Performance Test Results\n")
            f.write("="*60 + "\n")
            for r in results:
                f.write(f"\nKey Size: {r['key_size']} bits\n")
                f.write(f"Encryption Time: {r['encryption_time']:.6f} seconds\n")
                f.write(f"Decryption Time: {r['decryption_time']:.6f} seconds\n")
        
        print(f"\nResults saved to: {results_file}")
        return results


def main_menu():
    """Display main menu and handle user input"""
    crypto = CryptoLab()
    
    while True:
        print("\n" + "="*60)
        print("CRYPTOGRAPHY LAB - Main Menu")
        print("="*60)
        print("1.  AES Encryption (128-bit ECB)")
        print("2.  AES Decryption (128-bit ECB)")
        print("3.  AES Encryption (128-bit CFB)")
        print("4.  AES Decryption (128-bit CFB)")
        print("5.  AES Encryption (256-bit ECB)")
        print("6.  AES Decryption (256-bit ECB)")
        print("7.  AES Encryption (256-bit CFB)")
        print("8.  AES Decryption (256-bit CFB)")
        print("9.  RSA Encryption")
        print("10. RSA Decryption")
        print("11. RSA Sign File")
        print("12. RSA Verify Signature")
        print("13. SHA-256 Hash File")
        print("14. Generate AES Keys")
        print("15. Generate RSA Keys")
        print("16. AES Performance Test")
        print("17. RSA Performance Test")
        print("0.  Exit")
        print("="*60)
        
        choice = input("Enter your choice: ").strip()
        
        try:
            if choice == '1':
                plaintext = input("Enter text to encrypt: ")
                crypto.aes_encrypt(plaintext, 128, 'ECB')
            
            elif choice == '2':
                crypto.aes_decrypt(128, 'ECB')
            
            elif choice == '3':
                plaintext = input("Enter text to encrypt: ")
                crypto.aes_encrypt(plaintext, 128, 'CFB')
            
            elif choice == '4':
                crypto.aes_decrypt(128, 'CFB')
            
            elif choice == '5':
                plaintext = input("Enter text to encrypt: ")
                crypto.aes_encrypt(plaintext, 256, 'ECB')
            
            elif choice == '6':
                crypto.aes_decrypt(256, 'ECB')
            
            elif choice == '7':
                plaintext = input("Enter text to encrypt: ")
                crypto.aes_encrypt(plaintext, 256, 'CFB')
            
            elif choice == '8':
                crypto.aes_decrypt(256, 'CFB')
            
            elif choice == '9':
                plaintext = input("Enter text to encrypt: ")
                key_size = int(input("Enter RSA key size (1024, 2048, 3072, 4096): "))
                crypto.rsa_encrypt(plaintext, key_size)
            
            elif choice == '10':
                key_size = int(input("Enter RSA key size (1024, 2048, 3072, 4096): "))
                crypto.rsa_decrypt(key_size)
            
            elif choice == '11':
                file_path = input("Enter file path to sign: ")
                key_size = int(input("Enter RSA key size (1024, 2048, 3072, 4096): "))
                crypto.rsa_sign(file_path, key_size)
            
            elif choice == '12':
                file_path = input("Enter original file path: ")
                signature_file = input("Enter signature file path: ")
                key_size = int(input("Enter RSA key size (1024, 2048, 3072, 4096): "))
                crypto.rsa_verify(file_path, signature_file, key_size)
            
            elif choice == '13':
                file_path = input("Enter file path to hash: ")
                crypto.sha256_hash(file_path)
            
            elif choice == '14':
                key_size = int(input("Enter AES key size (128 or 256): "))
                crypto.generate_aes_key(key_size)
            
            elif choice == '15':
                key_size = int(input("Enter RSA key size (1024, 2048, 3072, 4096): "))
                crypto.generate_rsa_keys(key_size)
            
            elif choice == '16':
                crypto.performance_test_aes()
            
            elif choice == '17':
                crypto.performance_test_rsa()
            
            elif choice == '0':
                print("Exiting program. Goodbye!")
                break
            
            else:
                print("Invalid choice. Please try again.")
        
        except Exception as e:
            print(f"Error: {str(e)}")
            print("Please try again.")


if __name__ == "__main__":
    main_menu()
