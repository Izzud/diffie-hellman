ROUNDS = 16
CHAR_SIZE = 8

initial_permutation = [ 58, 50, 42, 34, 26, 18, 10, 2, 
                        60, 52, 44, 36, 28, 20, 12, 4, 
                        62, 54, 46, 38, 30, 22, 14, 6,
                        64, 56, 48, 40, 32, 24, 16, 8,
                        57, 49, 41, 33, 25, 17, 9, 1,
                        59, 51, 43, 35, 27, 19, 11, 3,
                        61, 53, 45, 37, 29, 21, 13, 5,
                        63, 55, 47, 39, 31, 23, 15, 7 ]

final_permutation =   [ 40, 8, 48, 16, 56, 24, 64, 32,
                        39, 7, 47, 15, 55, 23, 63, 31,
                        38, 6, 46, 14, 54, 22, 62, 30,
                        37, 5, 45, 13, 53, 21, 61, 29,
                        36, 4, 44, 12, 52, 20, 60, 28,
                        35, 3, 43, 11, 51, 19, 59, 27,
                        34, 2, 42, 10, 50, 18, 58, 26,
                        33, 1, 41, 9, 49, 17, 57, 25 ]

expansion  =  [ 32, 1, 2, 3, 4, 5,
                4, 5, 6, 7, 8, 9,
                8, 9, 10, 11, 12, 13,
                12, 13, 14, 15, 16, 17,
                16, 17, 18, 19, 20, 21,
                20, 21, 22, 23, 24, 25,
                24, 25, 26, 27, 28, 29,
                28, 29, 30, 31, 32, 1 ]

permuted_choice_1  =  [ # Left
                        57, 49, 41, 33, 25, 17, 9,
                        1, 58, 50, 42, 34, 26, 18,
                        10, 2, 59, 51, 43, 35, 27,
                        19, 11, 3, 60, 52, 44, 36,
                        # Right
                        63, 55, 47, 39, 31, 23, 15,
                        7, 62, 54, 46, 38, 30, 22,
                        14, 6, 61, 53, 45, 37, 29,
                        21, 13, 5, 28, 20, 12, 4 ]

permuted_choice_2  =  [ 14, 17, 11, 24, 1, 5,
                        3, 28, 15, 6, 21, 10,
                        23, 19, 12, 4, 26, 8,
                        16, 7, 27, 20, 13, 2,
                        41, 52, 31, 37, 47, 55,
                        30, 40, 51, 45, 33, 48,
                        44, 49, 39, 56, 34, 53,
                        46, 42, 50, 36, 29, 32 ]

S_BOX = [
        [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
        ],

        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
        ],

        [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
        ],

        [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
        ],  

        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
        ], 

        [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
        ], 

        [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
        ],
        
        [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
        ]
        ]

#Permutation after each SBox substitution
P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

bits_shift = [ 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 ]

def string_to_bit_array(string):                                                            # Convert a string into a list of bits
    array = list()
    for char in string:
        binval = 0
        if isinstance(char, int):
            binval =  bin(char)[2:]                                                         # Cut '0b' from bin() result
        else: 
            binval = bin(ord(char))[2:]
        
        # Add 0 if len < 8
        if len(binval) > CHAR_SIZE:
            raise "binary value larger than the expected size"

        while len(binval) < CHAR_SIZE:
            binval = "0" + binval
        
        # print(binval)
        array.extend([int(x) for x in list(binval)])                                        # Add each bits from binval to the final list
    return array

def bit_array_to_string(array):                                                             # Recreate the string from the bit array
    res = ''.join( [ chr(int(y,2)) for y in                                                 # convert the bytes into into char
                    [ ''.join([str(x) for x in _bytes]) for _bytes in nsplit(array,8)]      # stitch a list of bits into a list of bytes (ex: [1,0,1,1,0,1,0,0, 1,0,0,0,0,1,1,1] into ['10110100', '1000111'])
            ])   
    return res

def bit_array_to_bin(array):
    res = ''.join( [ ''.join([str(x) for x in _bytes]) for _bytes in nsplit(array,8)])      # stitch a list of bits into a list of bytes (ex: [1,0,1,1,0,1,0,0, 1,0,0,0,0,1,1,1] into ['10110100', '1000111'])
    return res

def nsplit(arr, n):                                                                         # Split a list into sublists of n
    return [ arr[k:k+n] for k in range(0, len(arr), n) ]

class DES:
    def __init__(self):
        self.plain_text = None
        self.password = None
        self.keys = []

    def run(self, key, text, action, padding):
        if len(key) < 8:
            raise "Key Should be 8 bytes long"
        elif len(key) > 8:
            key = key[:8]
        
        self.password = key
        self.plain_text = text
        
        # add padding
        if padding and action == 'ENCRYPT':
            self.addPadding()
        elif len(self.plain_text) % 8 != 0:
            raise "Data size should be multiple of 8 bytes!"
        
        self.generatekeys()
        # print(self.keys)

        text_blocks = nsplit(self.plain_text, 8)                                            # Split the text in blocks of 8 bytes (64 bits total)
        result = []

        for block in text_blocks:

            block = string_to_bit_array(block)
            block = self.permute(block, initial_permutation)

            left, right = nsplit(block, 32)                                                 # Split block into half (64bits -> 2x 32bits)
            tmp = None

            for i in range(ROUNDS):
                expanded = self.permute(right, expansion)                                   # Expand d to match Ki size (32bits -> 48bits)

                if action == 'ENCRYPT':
                    tmp = self.xor(self.keys[i], expanded)
                else:
                    tmp = self.xor(self.keys[15-i], expanded)                               # If decrypting start from the last key

                tmp = self.substitute(tmp)                                                  # Subtitute w/ S-BOX

                tmp = self.permute(tmp, P)

                tmp = self.xor(left, tmp)                                                   

                left = right
                right = tmp

            result += self.permute(right + left, final_permutation)

        final_res = bit_array_to_string(result)
        # final_res = result

        # if (action == 'ENCRYPT'):
        #     final_res = bit_array_to_hex(result)

        if padding and action == 'DECRYPT':
            return self.removePadding(final_res)                                            # Remove the padding from decrypted data
        else:
            return final_res

        return final_res
    

    def generatekeys(self):
        self.keys = []

        key = string_to_bit_array(self.password)

        key = self.permute(key, permuted_choice_1)                                                  # Apply the initial permute on the key (64bits -> 56bits)
        left, right = nsplit(key, 28)                                                               # Split key into two

        for i in range(ROUNDS):
            left, right = self.shift(left, right, bits_shift[i])
            merged = left + right
            self.keys.append(self.permute(merged, permuted_choice_2))                               # Apply permuted_choice_2 (56bits -> 48bits) to key and append to key lists

    def substitute(self, data):
        subblocks = nsplit(data, 6)                                                                 # Split bit array into sublist of 6 bits (48bits -> 8x 6bits)
        result = []

        for i in range(len(subblocks)): 
            block = subblocks[i]

            row = int(str(block[0])+str(block[5]), 2)                                                # Get the row with the first and last bit
            column = int(''.join([str(x) for x in block[1:][:-1]]), 2)   
            val = S_BOX[i][row][column]

            binval = 0

            # convert S_BOX val to binary

            if isinstance(val, int):
                binval =  bin(val)[2:]                                                              # Cut '0b' from bin() result
            else: 
                binval = bin(ord(val))[2:]                                                          # Get ascii val of char and convert it to binary
            
            if len(binval) > 4:
                raise "binary value larger than the expected size"
            while len(binval) < 4:
                binval = "0" + binval  
                                                                 
            result += [int(x) for x in binval]

        # print(result)
        return result

    def permute(self, block, table):                                                        # Permute the given block using the given table
        res = [block[x-1] for x in table]
        return res
    
    def xor(self, t1, t2):
        XOR = [ x^y for x,y in zip(t1, t2)]                                                 # Apply a xor and return the resulting list
        return XOR

    def shift(self, left, right, n):
        shifted = left[n:] + left[:n], right[n:] + right[:n]                                                         
        return shifted
    
    # PKCS5 padding (https://www.cryptosys.net/pki/manpki/pki_paddingschemes.html)
    def addPadding(self):                                                                   # Add padding to the datas using PKCS5 spec
        pad_len = 8 - (len(self.plain_text) % 8)
        self.plain_text += pad_len * chr(pad_len)
    
    def removePadding(self, data):                                                          # Remove the padding of the plain text (it assume there is padding)
        pad_len = ord(data[-1])
        return data[:-pad_len]

    def encrypt(self, key, text, padding=True):
        return self.run(key, text, 'ENCRYPT', padding)
    
    def decrypt(self, key, text, padding=True):
        return self.run(key, text, 'DECRYPT', padding)

# if __name__ == '__main__':
#     print("===================== TEST =====================")

#     # String
#     key = "45454545"
#     plain_text = "9999999999"

#     # Key (hex)
#     # key = bytes.fromhex('3435343534353435').decode('utf-8')
#     cipher_text = bytes.fromhex('5ec28dc2b0c3b9c28e3fc283c3a5083a191a22c29cc3a318').decode('utf-8')

#     print("Plain text: {}".format(plain_text))
#     print("Key: {}".format(key))
#     print("Plain text (Hex): {}".format(plain_text.encode('utf-8').hex()))
#     print("Key (Hex): {}".format(key.encode('utf-8').hex()))

#     des = DES()
#     # cipher_text = des.encrypt(key,plain_text)
#     decrypted = des.decrypt(key,cipher_text)


#     # print(hex(int(bit_array_to_bin(cipher_text),2)))
#     # # print(bit_array_to_string(decrypted)[:-ord(decrypted[-1])])

#     # print("\nCipher text (as String): %r" % cipher_text)
#     # print("Cipher text (Hex): {}" .format(cipher_text.encode('utf-8').hex()))
    
#     print("Deciphered: ", decrypted)

#     # plain_text = input("\n\nEnter plaintext: ")
#     # key = input("Enter key: ")

#     # des = DES()
#     # cipher_text = des.encrypt(key,plain_text)
#     # decrypted = des.decrypt(key,cipher_text)

#     # print("Plain text (Hex): {}".format(plain_text.encode('utf-8').hex()))
#     # print("Key (Hex): {}".format(key.encode('utf-8').hex()))
#     # print("Cipher text (as String): %r" % cipher_text)
#     # print("Cipher text (Hex): {}" .format(cipher_text.encode('utf-8').hex()))
#     # print("Deciphered: ", decrypted)


