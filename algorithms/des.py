# This program contains an implementation of the DES encryption algorithm

# Some precalculated data needed for conversions and transformations

from tkinter import Message
from algorithms.utils import *

# hex_to_bin = {'0': '0000', '1': '0001', '2': '0010', '3': '0011', '4': '0100', '5': '0101', '6': '0110', '7': '0111', '8': '1000', '9': '1001', 'a': '1010', 'b': '1011', 'c': '1100', 'd': '1101', 'e': '1110', 'f': '1111'}
# bin_to_hex = {'0000': '0', '0001': '1', '0010': '2', '0011': '3', '0100': '4', '0101': '5', '0110': '6', '0111': '7', '1000': '8', '1001': '9', '1010': 'a', '1011': 'b', '1100': 'c', '1101': 'd', '1110': 'e', '1111': 'f'}

key_permutation1 = [57, 49, 41, 33, 25, 17, 9, 
                        1, 58, 50, 42, 34, 26, 18, 
                    10, 2, 59, 51, 43, 35, 27, 
                    19, 11, 3, 60, 52, 44, 36, 
                    63, 55, 47, 39, 31, 23, 15, 
                        7, 62, 54, 46, 38, 30, 22, 
                    14, 6, 61, 53, 45, 37, 29, 
                    21, 13, 5, 28, 20, 12, 4 ]

key_permutation2 = [14, 17, 11, 24, 1, 5, 
                    3, 28, 15, 6, 21, 10, 
                    23, 19, 12, 4, 26, 8, 
                    16, 7, 27, 20, 13, 2, 
                    41, 52, 31, 37, 47, 55, 
                    30, 40, 51, 45, 33, 48, 
                    44, 49, 39, 56, 34, 53, 
                    46, 42, 50, 36, 29, 32 ]
    
shifts = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

initial_permutation = [58, 50, 42, 34, 26, 18, 10, 2, 
                           60, 52, 44, 36, 28, 20, 12, 4, 
                           62, 54, 46, 38, 30, 22, 14, 6, 
                           64, 56, 48, 40, 32, 24, 16, 8, 
                           57, 49, 41, 33, 25, 17, 9, 1, 
                           59, 51, 43, 35, 27, 19, 11, 3, 
                           61, 53, 45, 37, 29, 21, 13, 5, 
                           63, 55, 47, 39, 31, 23, 15, 7] 

final_permutation = [ 40, 8, 48, 16, 56, 24, 64, 32, 
                      39, 7, 47, 15, 55, 23, 63, 31, 
                      38, 6, 46, 14, 54, 22, 62, 30, 
                      37, 5, 45, 13, 53, 21, 61, 29, 
                      36, 4, 44, 12, 52, 20, 60, 28, 
                      35, 3, 43, 11, 51, 19, 59, 27, 
                      34, 2, 42, 10, 50, 18, 58, 26, 
                      33, 1, 41, 9, 49, 17, 57, 25 ]

sboxes =    [[['e', '4', 'd', '1', '2', 'f', 'b', '8', '3', 'a', '6', 'c', '5', '9', '0', '7'], 
                ['0', 'f', '7', '4', 'e', '2', 'd', '1', 'a', '6', 'c', 'b', '9', '5', '3', '8'], 
                ['4', '1', 'e', '8', 'd', '6', '2', 'b', 'f', 'c', '9', '7', '3', 'a', '5', '0'], 
                ['f', 'c', '8', '2', '4', '9', '1', '7', '5', 'b', '3', 'e', 'a', '0', '6', 'd']],

                [['f', '1', '8', 'e', '6', 'b', '3', '4', '9', '7', '2', 'd', 'c', '0', '5', 'a'], 
                ['3', 'd', '4', '7', 'f', '2', '8', 'e', 'c', '0', '1', 'a', '6', '9', 'b', '5'], 
                ['0', 'e', '7', 'b', 'a', '4', 'd', '1', '5', '8', 'c', '6', '9', '3', '2', 'f'], 
                ['d', '8', 'a', '1', '3', 'f', '4', '2', 'b', '6', '7', 'c', '0', '5', 'e', '9']],

                [['a', '0', '9', 'e', '6', '3', 'f', '5', '1', 'd', 'c', '7', 'b', '4', '2', '8'], 
                ['d', '7', '0', '9', '3', '4', '6', 'a', '2', '8', '5', 'e', 'c', 'b', 'f', '1'], 
                ['d', '6', '4', '9', '8', 'f', '3', '0', 'b', '1', '2', 'c', '5', 'a', 'e', '7'], 
                ['1', 'a', 'd', '0', '6', '9', '8', '7', '4', 'f', 'e', '3', 'b', '5', '2', 'c']],
            
                [['7', 'd', 'e', '3', '0', '6', '9', 'a', '1', '2', '8', '5', 'b', 'c', '4', 'f'], 
                ['d', '8', 'b', '5', '6', 'f', '0', '3', '4', '7', '2', 'c', '1', 'a', 'e', '9'], 
                ['a', '6', '9', '0', 'c', 'b', '7', 'd', 'f', '1', '3', 'e', '5', '2', '8', '4'], 
                ['3', 'f', '0', '6', 'a', '1', 'd', '8', '9', '4', '5', 'b', 'c', '7', '2', 'e']],

                [['2', 'c', '4', '1', '7', 'a', 'b', '6', '8', '5', '3', 'f', 'd', '0', 'e', '9'], 
                ['e', 'b', '2', 'c', '4', '7', 'd', '1', '5', '0', 'f', 'a', '3', '9', '8', '6'], 
                ['4', '2', '1', 'b', 'a', 'd', '7', '8', 'f', '9', 'c', '5', '6', '3', '0', 'e'], 
                ['b', '8', 'c', '7', '1', 'e', '2', 'd', '6', 'f', '0', '9', 'a', '4', '5', '3']],

                [['c', '1', 'a', 'f', '9', '2', '6', '8', '0', 'd', '3', '4', 'e', '7', '5', 'b'], 
                ['a', 'f', '4', '2', '7', 'c', '9', '5', '6', '1', 'd', 'e', '0', 'b', '3', '8'], 
                ['9', 'e', 'f', '5', '2', '8', 'c', '3', '7', '0', '4', 'a', '1', 'd', 'b', '6'], 
                ['4', '3', '2', 'c', '9', '5', 'f', 'a', 'b', 'e', '1', '7', '6', '0', '8', 'd']],

                [['4', 'b', '2', 'e', 'f', '0', '8', 'd', '3', 'c', '9', '7', '5', 'a', '6', '1'], 
                ['d', '0', 'b', '7', '4', '9', '1', 'a', 'e', '3', '5', 'c', '2', 'f', '8', '6'], 
                ['1', '4', 'b', 'd', 'c', '3', '7', 'e', 'a', 'f', '6', '8', '0', '5', '9', '2'], 
                ['6', 'b', 'd', '8', '1', '4', 'a', '7', '9', '5', '0', 'f', 'e', '2', '3', 'c']],

                [['d', '2', '8', '4', '6', 'f', 'b', '1', 'a', '9', '3', 'e', '5', '0', 'c', '7'], 
                ['1', 'f', 'd', '8', 'a', '3', '7', '4', 'c', '5', '6', 'b', '0', 'e', '9', '2'], 
                ['7', 'b', '4', '1', '9', 'c', 'e', '2', '0', '6', 'a', 'd', 'f', '3', '5', '8'], 
                ['2', '1', 'e', '7', '4', 'a', '8', 'd', 'f', 'c', '9', '0', '3', '5', '6', 'b']]]
    
perm = [16,  7, 20, 21,
        29, 12, 28, 17, 
        1, 15, 23, 26, 
        5, 18, 31, 10, 
        2,  8, 24, 14, 
        32, 27,  3,  9, 
        19, 13, 30,  6, 
        22, 11,  4, 25 ]

def get_subkeys(key_bin):
    '''
    Function to generate 16 subkeys of 48 bits each given an input key of 64 bits
    Argument:
            key: 64 bit key
    Returns:
            subkeys: list containing 16 subkeys of 48 bits each
    '''

    # generate 56 bit key from input using the table key_permutation1
    key_56bit = ''.join(key_bin[i - 1] for i in key_permutation1)
    key_lefts, key_rights = [key_56bit[0:28]], [key_56bit[28:]]

    # generate 16 subkeys based on the shift values 
    for val in shifts:
        key_lefts.append(key_lefts[-1][val:] + key_lefts[-1][:val])
        key_rights.append(key_rights[-1][val:] + key_rights[-1][:val])

    subkeys = [key_lefts[i] + key_rights[i] for i in range(1,17)]

    # for each subkey of size 56 bits, reduce its size to 48 bits using key_permutation2
    for i in range(16):
        subkeys[i] = ''.join([subkeys[i][j-1] for j in key_permutation2])
    
    return subkeys

def expand_bits(ciphertext):
    '''
    This function expands a block of 32 bits to 48 bits
    Argument:
            ciphertext: 32 bit binary string
    Returns:
            ciphertext: 48 bit binary string
    '''
    expansion_table = [32, 1 , 2 , 3 , 4 , 5 , 4 , 5, 
                       6 , 7 , 8 , 9 , 8 , 9 , 10, 11, 
                       12, 13, 12, 13, 14, 15, 16, 17, 
                       16, 17, 18, 19, 20, 21, 20, 21, 
                       22, 23, 24, 25, 24, 25, 26, 27, 
                       28, 29, 28, 29, 30, 31, 32, 1 ]

    ciphertext_48bits = ''.join([ciphertext[i-1] for i in expansion_table])

    return ciphertext_48bits

def transform(right, subkeys, i):
    '''
    Function to transform the right half of the ciphertext 
    Arguments:
            right: binary string containing the right half of the ciphertext
            i: integer denoting round of encryption. Ranges from [0,16)
    Returns:
            transform: string containing the transformed version of right
    '''
    right = expand_bits(right)
    xored_right = xor(right,subkeys[i])
    transform = ''
    for i in range(0,len(xored_right),6):
        block = xored_right[i:i+6]
        row = int('00' + block[0] + block[-1],2)
        col = int(block[1:5],2)
        transform += hex_to_bin[sboxes[i // 6][row][col]]

    transform = ''.join([transform[i-1] for i in perm])
    return transform

def DES(plaintext, subkeys):
    '''
    Function to apply the DES algorithm to a 64 bit block of data
    Arguments:
            plaintext: 64 bit block of the original plaintext
            subkeys: list containing 16 keys, one for each round
    Returns:
            ciphertext_hex: hex string obtained after encryption of the plaintext
    '''

    plaintext = ''.join([plaintext[i-1] for i in initial_permutation])
    left, right = plaintext[:32], plaintext[32:]

    # For each round: left = right, right = left XOR transform(right) [updates must be simultaneous]
    for i in range(16):
        temp_left = right
        right = xor(left, transform(right, subkeys, i))
        left = temp_left
    ciphertext = right + left

    # final permutation
    ciphertext = ''.join([ciphertext[i-1] for i in final_permutation])

    # convert binary string to hex string and return
    ciphertext_hex = ''
    for i in range(0,64,4):
        ciphertext_hex += bin_to_hex[ciphertext[i:i+4]]
    return ciphertext_hex

# function to encrypt a message given the subkeys
def des_encrypt(message, subkeys):
    message = add_padding(message)
    ciphertext = ''
    for i in range(0,len(message),8):
        block = message[i:i+8]
        message_bin = hex_to_binary(ascii_to_hex(block))
        ciphertext += DES(message_bin,subkeys)
    
    return ciphertext

# function to decrypt the ciphertext given the subkeys
def des_decrypt(ciphertext, subkeys):
    plaintext = ''
    for i in range(0,len(ciphertext),16):
        block = ciphertext[i:i+16]
        block_bin = hex_to_binary(block)
        plaintext += hex_to_ascii(DES(block_bin,subkeys))

    return plaintext