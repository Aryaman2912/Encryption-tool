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
def get_binary(hex_string):
    bin_string = ''
    for c in hex_string:
        bin_string += hex_to_bin[c]
    
    return bin_string