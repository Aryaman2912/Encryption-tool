hex_to_bin = {'0': '0000', '1': '0001', '2': '0010', '3': '0011', '4': '0100', '5': '0101', '6': '0110', '7': '0111', '8': '1000', '9': '1001', 'a': '1010', 'b': '1011', 'c': '1100', 'd': '1101', 'e': '1110', 'f': '1111'}
bin_to_hex = {'0000': '0', '0001': '1', '0010': '2', '0011': '3', '0100': '4', '0101': '5', '0110': '6', '0111': '7', '1000': '8', '1001': '9', '1010': 'a', '1011': 'b', '1100': 'c', '1101': 'd', '1110': 'e', '1111': 'f'}

# Function to convert an ascii message to hex
def ascii_to_hex(message):

    hex_message = ''
    for c in message:
        hex_message += hex(ord(c))[2:]

    return hex_message

# Function to convert a hex string to ascii
def hex_to_ascii(hex_message):
    
    message = ''
    for i in range(0,len(hex_message),2):
        message += chr(int('0x' + hex_message[i:i+2], 16))
    
    return message
    
# Function to convert a hexadecimal string to binary string
def hex_to_binary(hex_string):
    bin_string = ''
    for c in hex_string:
        bin_string += hex_to_bin[c]
    
    return bin_string

# Function to convert a binary string to a hexadecimal string
def binary_to_hex(bin_string):
    
    hex_string = ''
    for i in range(0,len(bin_string),4):
        hex_string += bin_to_hex[bin_string[i:i+4]]
    
    return hex_string

# Function to convert an integer to a binary string
def int_to_binary(value):
    mapping = {0:'0',1:'1'}
    bin_string = ''
    while value:
        bin_string += mapping[value % 2]
        value = value // 2
    while len(bin_string) % 4:
        bin_string += '0'
    return bin_string[::-1]

# Function to perform modular exponentation
def mod_exp(num, e, mod):
    ciphertext = 1

    num = num % mod
    if num == 0:
        return 0

    while e > 0:
        if e % 2:
            ciphertext = (ciphertext * num) % mod
        
        e = e // 2
        num = (num * num) % mod
    
    return ciphertext

# Function to find the multiplicative inverse of e mod phi
def multiplicative_inverse(e, phi):
    d = 0
    x1 = 0
    x2 = 1
    y1 = 1
    temp = phi

    while e > 0:
        temp1 = temp // e
        temp2 = temp - temp1 * e
        temp = e
        e = temp2

        x = x2 - temp1 * x1
        y = d - temp1 * y1

        x2 = x1
        x1 = x
        d = y1
        y1 = y
    
    if temp == 1:
        return d + phi

# Function to get xor of two binary strings
def xor(s1, s2):
    result = ''
    for i in range(len(s1)):
        result += str(int(not(s1[i] == s2[i])))
    
    return result

# Function to add padding to a message by adding spaces at the end
def add_padding(message):
    while len(message) % 8 != 0:
        message += ' '
    return message

# Function to remove padding from a message by removing any spaces at the end
def remove_padding(message):

    while message[-1] == ' ':
        message.pop()
    
    return message