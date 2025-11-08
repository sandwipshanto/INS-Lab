def break_caesar_cipher(ciphertext):
    
    # Try all possible shifts
    for shift in range(26):
        plaintext = ""
        
        for char in ciphertext:
            if char.isalpha():
                if char.isupper():
                    plaintext += chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
                else:
                    plaintext += chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
            else:
                plaintext += char
        
        print(f"Shift {shift:2d}: {plaintext}")


# Main execution
if __name__ == "__main__":
    cipher = "odroboewscdrolocdcwkbdmyxdbkmdzvkdpybwyeddrobo"
    
    print("Caesar Cipher Breaker")
    print(f"Ciphertext: {cipher}\n")
    
    break_caesar_cipher(cipher)
    
    print(f"\nAnswer: Shift 10 gives readable text")
