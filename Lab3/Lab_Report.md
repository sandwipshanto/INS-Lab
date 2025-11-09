# Lab Report: Symmetric Encryption & Hashing (Lab 3)

---

## Objectives
- To perform symmetric encryption and hashing using OpenSSL and hex editors.
- To compare cryptographic modes and hash algorithms in depth.

---

## Setup

### Hex Editor (GHex)
GHex installed and used for binary file inspection:
```bash
sudo apt-get install ghex
ghex filename &
```
GHex allows inspecting and editing hex bytes, essential for tasks involving file header manipulation and bit-flipping for corruption experiments.

### OpenSSL Verification
OpenSSL installed and checked:
```bash
openssl
# If not present:
sudo apt-get install openssl
```

---

## Task 1: AES Encryption Using Different Modes

**Objective:** Encrypt a text file using at least three symmetric ciphers/modes, then decrypt to verify functionality.

**Commands Used:**  
[Lab3/task1](https://github.com/sandwipshanto/INS-Lab/tree/83ae60b54a6f750f80eadd819e1cb4709b9668a7/Lab3/task1)  
_(No direct command files found. Below command templates reflect standard procedure)_

```bash

echo "This is a test message for encryption lab. Symmetric encryption is fun!" > plain.txt

 KEY=00112233445566778899aabbccddeeff

IV=0102030405060708090a0b0c0d0e0f10

openssl enc -aes-128-cbc -e -in plain.txt -out enc_cbc.bin -K $KEY -iv $IV

openssl enc -aes-128-ecb -e -in plain.txt -out enc_ecb.bin -K 00112233445566778899aabbccddeeff


openssl enc -aes-128-ecb -e -in plain.txt -out enc_ecb.bin -K $KEY

openssl enc -aes-128-cfb -e -in plain.txt -out enc_cfb.bin -K $KEY -iv $IV

openssl enc -aes-128-cbc -d -in enc_cbc.bin -out dec_cbc.txt -K $KEY -iv $IV

openssl enc -aes-128-ecb -d -in enc_ecb.bin -out dec_ecb.txt -K $KEY

openssl enc -aes-128-cfb -d -in enc_cfb.bin -out dec_cfb.txt -K $KEY -iv $IV
```

---

## Task 2: Encryption Mode – ECB vs CBC

**Objective:** Encrypt a BMP image using ECB and CBC, observe info leakage by comparing images.

**Commands Used:**  
File: [`Lab3/task2/commands`](https://github.com/sandwipshanto/INS-Lab/blob/83ae60b54a6f750f80eadd819e1cb4709b9668a7/Lab3/task2/commands)  
```
wget https://github.com/ashutosh1206/Cryptography/blob/master/AES-Image-Encryption/test.bmp?raw=true -O original.bmp

head -c 54 original.bmp > header.bmp
tail -c +55 original.bmp > body.bin

KEY=00112233445566778899aabbccddeeff
ID=0102030405060708090a0b0c0d0e0f10

openssl enc -aes-128-ecb -e -in body.bin -out enc_ecb.bin -K 00112233445566778899aabbccddeeff -nosalt

openssl enc -aes-128-cbc -e -in body.bin -out enc_cbc.bin -K 00112233445566778899aabbccddeeff -iv 0102030405060708 -nosalt

cat header.bmp enc_ecb.bin > enc_ecb.bmp
cat header.bmp enc_cbc.bin > enc_cbc.bmp

eog enc_ecb.bmp
eog enc_cbc.bmp
```
Header replacement with GHex and image viewing as directed in manual.

**Discussion:**  
When viewed, ECB encryption tends to reveal visible patterns from the original due to lack of block chaining, CBC fully obfuscates image content.

---

## Task 3: Encryption Mode – Corrupted Cipher Text

**Objective:** Test resilience to bit corruption for various encryption modes.

**Commands Used:**  
File: [`Lab3/task3/commands`](https://github.com/sandwipshanto/INS-Lab/blob/83ae60b54a6f750f80eadd819e1cb4709b9668a7/Lab3/task3/commands)  
```bash
openssl enc -aes-128-ecb -e -in plain.txt -out enc_ecb.bin -K $KEY -nosalt
openssl enc -aes-128-cbc -e -in plain.txt -out enc_cbc.bin -K $KEY -iv $IV -nosalt
openssl enc -aes-128-cfb -e -in plain.txt -out enc_cfb.bin -K $KEY -iv $IV -nosalt
openssl enc -aes-128-ofb -e -in plain.txt -out enc_ofb.bin -K $KEY -iv $IV -nosalt
  
ghex enc_ecb.bin
ghex enc_cbc.bin
ghex enc_cfb.bin
ghex enc_ofb.bin

openssl enc -aes-128-ecb -d -in enc_ecb.bin -out dec_ecb_corrupted.txt -K $KEY -nosalt
openssl enc -aes-128-cbc -d -in enc_cbc.bin -out dec_cbc_corrupted.txt -K $KEY -iv $IV -nosalt
openssl enc -aes-128-cfb -d -in enc_cfb.bin -out dec_cfb_corrupted.txt -K $KEY -iv $IV -nosalt
openssl enc -aes-128-ofb -d -in enc_ofb.bin -out dec_ofb_corrupted.txt -K $KEY -iv $IV -nosalt

cat dec_ecb_corrupted.txt
cat dec_cbc_corrupted.txt
cat dec_cfb_corrupted.txt
cat dec_ofb_corrupted.txt
```
**Discussion Before/After:**
- ECB: Only affected block is corrupted.
- CBC: Corruption affects current and next block.
- CFB: Only one byte affected.
- OFB: One byte affected.

---

## Task 4: Padding

**Objective:**  
Determine padding requirements for various cipher modes.

**Commands Used:**  
File: [`Lab3/task4/commands`](https://github.com/sandwipshanto/INS-Lab/blob/83ae60b54a6f750f80eadd819e1cb4709b9668a7/Lab3/task4/commands)
```bash
echo "Hello World" > test_padding.txt

ls -l test_padding.txt

openssl enc -aes-128-ecb -e -in test_padding.txt -out ecb_encrypted.bin -K $KEY

ls -l ecb_encrypted.bin

openssl enc -aes-128-cbc -e -in test_padding.txt -out cbc_encrypted.bin -K $KEY -iv $IV

ls -l cbc_encrypted.bin

openssl enc -aes-128-cfb -e -in test_padding.txt -out cfb_encrypted.bin -K $KEY -iv $IV

ls -l cfb_encrypted.bin

openssl enc -aes-128-ofb -e -in test_padding.txt -out ofb_encrypted.bin -K $KEY -iv $IV

ls -l ofb_encrypted.bin
```
**Observation:**
- Padding is needed for ECB and CBC.
- CFB and OFB (stream modes) do not use padding.

---

## Task 5: Generating Message Digest

**Objective:**  
Generate file digests using multiple hash algorithms.

**Commands/Outputs:**  
File: [`Lab3/task5/commands`](https://github.com/sandwipshanto/INS-Lab/blob/83ae60b54a6f750f80eadd819e1cb4709b9668a7/Lab3/task5/commands)  
File: [`Lab3/task5/outputs`](https://github.com/sandwipshanto/INS-Lab/blob/83ae60b54a6f750f80eadd819e1cb4709b9668a7/Lab3/task5/outputs)
```bash
gedit digest_test.txt

openssl dgst -md5 digest_test.txt

openssl dgst -sha1 digest_test.txt

openssl dgst -sha256 digest_test.txt

openssl dgst -sha512 digest_test.txt
```
**Observation:**  
Output digests show differences in size and format: MD5 (128-bit), SHA1 (160-bit), SHA256 (256-bit).

---

## Task 6: Keyed hash and HMAC

**Objective:**  
Generate MACs using HMAC with different keys and algorithms.

**Commands/Outputs:**  
File: [`Lab3/task6/commands`](https://github.com/sandwipshanto/INS-Lab/blob/83ae60b54a6f750f80eadd819e1cb4709b9668a7/Lab3/task6/commands)  
File: [`Lab3/task6/outputs`](https://github.com/sandwipshanto/INS-Lab/blob/83ae60b54a6f750f80eadd819e1cb4709b9668a7/Lab3/task6/outputs)
```bash
gedit hmac_test.txt

openssl dgst -md5 -hmac "abc" hmac_test.txt
openssl dgst -md5 -hmac "mySecretKey123" hmac_test.txt
openssl dgst -md5 -hmac "thisIsAVeryLongSecretKeyForHMACGeneration" hmac_test.txt

openssl dgst -sha256 -hmac "abc" hmac_test.txt
openssl dgst -sha256 -hmac "mySecretKey123" hmac_test.txt
openssl dgst -sha256 -hmac "thisIsAVeryLongSecretKeyForHMACGeneration" hmac_test.txt

openssl dgst -sha1 -hmac "abc" hmac_test.txt
openssl dgst -sha1 -hmac "mySecretKey123" hmac_test.txt
openssl dgst -sha1 -hmac "thisIsAVeryLongSecretKeyForHMACGeneration" hmac_test.txt
```
**Discussion:**  
HMAC works for keys of any length; internally, keys are hashed/truncated as needed.

---

## Task 7: Hash Randomness (Bonus)

**Objective:**  
Test hash avalanche effect by flipping one bit in input.

**Commands/Outputs:**  
File: [`Lab3/task7/commands`](https://github.com/sandwipshanto/INS-Lab/blob/83ae60b54a6f750f80eadd819e1cb4709b9668a7/Lab3/task7/commands)  
File: [`Lab3/task7/outputs`](https://github.com/sandwipshanto/INS-Lab/blob/83ae60b54a6f750f80eadd819e1cb4709b9668a7/Lab3/task7/outputs)
```bash
gedit hash_randomness.txt

openssl dgst -md5 hash_randomness.txt

openssl dgst -sha256 hash_randomness.txt

ghex hash_randomness.txt &

openssl dgst -md5 hash_randomness.txt

openssl dgst -sha256 hash_randomness.txt
```
**Observation:**  
Hash output changes dramatically with even a single-bit change in input, confirming strong avalanche property.

---

## Attachments  
_(Attach all referenced files as required by lab manual: encrypted files, digests, images, etc. See links above for sources in repo.)_

---

## References
- [Lab3 folder on GitHub](https://github.com/sandwipshanto/INS-Lab/tree/83ae60b54a6f750f80eadd819e1cb4709b9668a7/Lab3)
- OpenSSL documentation (`man openssl`, `man enc`, `man dgst`)
- Hex Editor (GHex)
- [Wikipedia: OpenSSL](https://en.wikipedia.org/wiki/OpenSSL)

---

**End of Report**
