from typing import Mapping


mapping = {'0':'0000','1':'0001','2':'0010','3':'0011','4':'0100','5':'0101','6':'0110','7':'0111','8':'1000','9':'1001','a':'1010','b':'1011','c':'1100','d':'1101','e':'1110','f':'1111'}

def get_subkeys(key):
    '''
    Function to generate 16 subkeys of 48 bits each given an input key of 64 bits
    Argument:
            key: 64 bit key
    Returns:
            subkeys: list containing 16 subkeys of 48 bits each
    '''

    key_bin = ''
    for c in key:
        key_bin += mapping[c]

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


def encrypt(ciphertext, subkeys):
    initial_permutation = [58, 50, 42, 34, 26, 18, 10, 2, 
                           60, 52, 44, 36, 28, 20, 12, 4, 
                           62, 54, 46, 38, 30, 22, 14, 6, 
                           64, 56, 48, 40, 32, 24, 16, 8, 
                           57, 49, 41, 33, 25, 17, 9, 1, 
                           59, 51, 43, 35, 27, 19, 11, 3, 
                           61, 53, 45, 37, 29, 21, 13, 5, 
                           63, 55, 47, 39, 31, 23, 15, 7] 
    
    ciphertext = ''.join([ciphertext[i-1] for i in initial_permutation])
    left, right = ciphertext[:32], ciphertext[32:]
if __name__ == '__main__':
    key = '133457799bbcdff1'

    subkeys = get_subkeys(key)
    