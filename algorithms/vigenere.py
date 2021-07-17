def vigenere_encrypt(plaintext, key):
    
    # list to store ciphertext
    ciphertext = []

    # variable to track the index of key being used
    i = 0
    # For each character, check if the character is uppercase or lowercase and then encrypt it accordingly
    for l in plaintext:

        # character is lowercase
        if l.islower():
            res = chr((ord(l) + ord(key[i].lower()) - 194) % 26 + ord('a')).lower()
        
        # character is uppercase
        elif l.isupper():
            res = chr((ord(l) + ord(key[i].upper()) - 130) % 26 + ord('A')).upper()
        
        # character is not part of the alphabet
        else:
            res = l

        ciphertext.append(res)

        # Ensure that i stays within key length
        i = (i + 1) % len(key)

    # Convert the list to string and return the ciphertext
    return (''.join(ciphertext))

def vigenere_decrypt(ciphertext, key):
    # variable to track the index of key being used
    i = 0

    # list to store plaintext
    plaintext = []

    # For each character, check if the character is uppercase or lowercase and then encrypt it accordingly
    for l in ciphertext:

        # character is lowercase
        if l.islower():
            res = chr((ord(l) - ord(key[i].lower()) + 26) % 26 + ord('a')).lower()
        
        # character is uppercase
        elif l.isupper():
            res = chr((ord(l) - ord(key[i].upper()) + 26) % 26 + ord('A')).upper()
        
        # character is not part of the alphabet
        else:
            res = l

        plaintext.append(res)

        # Ensure that i stays within key length
        i = (i + 1) % len(key)

    # Convert the list to string and return the ciphertext
    return (''.join(plaintext))

def vigenere_key_gen():
    pass