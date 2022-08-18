# This code gets the encryption key leveraging the fact that inside the file named "latin_alphabet.txt"
# should be the latin alphabet (ABCD...). Thanks to this, the XOR and ROL operations can be reversed.

def rightshift(n, d, N):  
    return (((n >> d) % (1 << N)) | (n << (N - d)) & 0xff)

def main():
    try:
        with open("..\\Files\\latin_alphabet.txt.encrypted", "rb") as f:
            bytes = f.read()
            letters = []
            
            for x in range(26):
                letters.append(x + 0x41)    # Fill an array with the ASCII decimal values for ABCD...
            
            # Reverse key from decoding mechanism:
            # ((input_key[i] ^ enc_bytes[i]) << i) - i
            i = 0
            res = []
            for b in bytes:                
                x3 = letters[i] + i

                try:
                    x2 = rightshift(x3, i, 8)
                    x1 = b ^ x2
                    res.append(chr(x1))
                    
                except:
                    print(f"Recovered key characters: {res}")
                    exit()

                i += 1                      

    except IOError:
        print('Error While Opening the file!')    

if __name__ == "__main__":
    main()