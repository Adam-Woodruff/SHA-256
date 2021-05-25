#from https://github.com/Adam-Woodruff/SHA-256/edit/main/SHA-256.py

import time

constants = (
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2)

def TxtInput():
    txt = input("input the text you want hashed")
    return txt 

def padding(message):
    """adds padding and marker to tell program when to stop
    """
    message.append(0x80)
    while (len(message) * 8 + 64) % 512 != 0:
        message.append(0x00)
    return message

def blocking(message):
    """splits the message in to an array of 64bit words
    """
    words = []
    for i in range(0, len(message), 64):
        words.append(message[i:i+64])
    return words

def Sigma0(word):
    word = RotateRight(word, 7) ^ RotateRight(word, 18) ^ (word >> 3)
    return word

def Sigma1(word):
    word = RotateRight(word, 17) ^ RotateRight(word, 19) ^ (word >> 10)
    return word

def UpperSigma0(word):
    word = RotateRight(word, 2) ^ RotateRight(word, 13) ^ RotateRight(word, 22)
    return word

def UpperSigma1(word):
    word = RotateRight(word, 6) ^ RotateRight(word, 11) ^ RotateRight(word, 25)
    return word

def majority(x, y, z):
    output = (x&y)^(x&z)^(y^z)
    return output

def choice(x, y, z):
    output = (x&y)^(~x&z)
    return output

def RotateRight(num, count):
    """rotates binary number the number of bits 
    specified by :count: to te right
    """
    for i in range(count):
        num &= (2**32-1)
        bit = num & 1
        num >>= 1
        if(bit):
            num |= (1 << (8-1))

    return num

def hashGen(message):
    #prep for hash generation
    message = bytearray(message, 'ascii')
    length = len(message) * 8
    message = padding(message)
    message = message + length.to_bytes(8, 'big')
    blocks = blocking(message)


    #creates a message schedule for each block of the message
    for block in blocks:
        message = []
        terms = []
        for t in range(0, 64):
            if t <= 15:
                message.append(bytes(block[t*4:(t*4)+4]))
            else:
                terms.append(Sigma1(int.from_bytes(message[t-2], 'big')))
                terms.append(int.from_bytes(message[t-7], 'big'))
                terms.append(Sigma0(int.from_bytes(message[t-15], 'big')))
                terms.append(int.from_bytes(message[t-16], 'big'))

                schedule = (sum(terms) % 2**32).to_bytes(4, 'big')
                message.append(schedule)

    h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x9b05688c, 0x510e527f, 0x1f83d9ab, 0x5be0cd19]

    Values = []
    for i in range(8):
        Values.append(h[i])

    #creates all 64 words 
    for i in range(64):
        t1 = (h[7] + UpperSigma1(h[4]) + choice(h[4], h[5], h[6]) + constants[i] + int.from_bytes(message[i], 'big')) % 2**32
        # t1 = (h[8] + constants[i] + int.from_bytes(message[i], 'big')) % 2**32
        t2 = (UpperSigma0(Values[0]) + majority(Values[0], Values[1], Values[2])) % 2**32
        Values[7] = Values[6]
        Values[6] = Values[5]
        Values[5] = Values[4]
        Values[4] = (Values[3] + t1) % 2**32
        Values[3] = Values[2]
        Values[2] = Values[1]
        Values[1] = Values[0]
        Values[0] = (t1 + t2) % 2**32

    for i in range(8):
        h[i] = (h[i] + Values[i]) % 2**32

    output = bytes()
    for i in range(8):
        output = output + (h[i]).to_bytes(4, 'big')
    return output

if __name__ == '__main__':
    while True:
        message = TxtInput()
        print(hashGen(message).hex())

        #record the time taken

        # start = time.time()
        # print(hashGen(message).hex())
        # end = time.time()
        # print(end - start)
