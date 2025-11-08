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
openssl enc -aes-128-cbc -e -in plain.txt -out cipher_cbc.bin -K 00112233445566778889aabbccddeeff -iv 0102030405060708
openssl enc -aes-128-cfb -e -in plain.txt -out cipher_cfb.bin -K 00112233445566778889aabbccddeeff -iv 0102030405060708
openssl enc -aes-128-ecb -e -in plain.txt -out cipher_ecb.bin -K 00112233445566778889aabbccddeeff
```
_Decryption (to verify):_
```bash
openssl enc -aes-128-cbc -d -in cipher_cbc.bin -out decrypted_cbc.txt -K 00112233445566778889aabbccddeeff -iv 0102030405060708
```

---

## Task 2: Encryption Mode – ECB vs CBC

**Objective:** Encrypt a BMP image using ECB and CBC, observe info leakage by comparing images.

**Commands Used:**  
File: [`Lab3/task2/commands`](https://github.com/sandwipshanto/INS-Lab/blob/83ae60b54a6f750f80eadd819e1cb4709b9668a7/Lab3/task2/commands)  
```
openssl enc -aes-128-ecb -e -in pic_original.bmp -out ecb_encrypted.bmp -K 00112233445566778889aabbccddeeff
openssl enc -aes-128-cbc -e -in pic_original.bmp -out cbc_encrypted.bmp -K 00112233445566778889aabbccddeeff -iv 0102030405060708
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
openssl enc -aes-128-ecb -e -in long.txt -out ecb.bin -K 00112233445566778889aabbccddeeff
openssl enc -aes-128-cbc -e -in long.txt -out cbc.bin -K 00112233445566778889aabbccddeeff -iv 0102030405060708
openssl enc -aes-128-cfb -e -in long.txt -out cfb.bin -K 00112233445566778889aabbccddeeff -iv 0102030405060708
openssl enc -aes-128-ofb -e -in long.txt -out ofb.bin -K 00112233445566778889aabbccddeeff -iv 0102030405060708

# Corrupt byte 30 in output using ghex, then decrypt:
openssl enc -aes-128-ecb -d -in ecb_corrupt.bin -out ecb_dec.txt -K 00112233445566778889aabbccddeeff
# CBC, CFB, OFB similarly
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
openssl enc -aes-128-cbc -e -in ibs.txt -out cbc_pad.bin -K 00112233445566778889aabbccddeeff -iv 0102030405060708
openssl enc -aes-128-ecb -e -in ibs.txt -out ecb_pad.bin -K 00112233445566778889aabbccddeeff
openssl enc -aes-128-cfb -e -in ibs.txt -out cfb_pad.bin -K 00112233445566778889aabbccddeeff -iv 0102030405060708
openssl enc -aes-128-ofb -e -in ibs.txt -out ofb_pad.bin -K 00112233445566778889aabbccddeeff -iv 0102030405060708
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
openssl dgst -md5 hash.txt
openssl dgst -sha1 hash.txt
openssl dgst -sha256 hash.txt
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
openssl dgst -md5 -hmac "key1" mac.txt
openssl dgst -sha256 -hmac "key2longer" mac.txt
openssl dgst -sha1 -hmac "anotherkey" mac.txt
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
openssl dgst -md5 rand.txt
# Modify a bit in rand.txt with ghex
openssl dgst -md5 rand_corrupt.txt
openssl dgst -sha256 rand.txt
openssl dgst -sha256 rand_corrupt.txt
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
