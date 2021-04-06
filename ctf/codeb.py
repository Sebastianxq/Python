import random
from Crypto.Util import number
from string import ascii_lowercase
import csv
import string


#euclids greatest common divisor
def egcd(a, b):
    x = 0 
    y = 1
    u = 1
    v = 0
    while a != 0:
        q = b//a 
        r = b % a
        m = x-u*q
        n = y-v*q
        b, a, x, y, u, v = a, r, u, v, m, n
        gcd = b
    return gcd, x, y


#Generate the public and private keys
def gen_keys(p, q):
    e = 65537
    n = p * q
    phi = (p - 1) * (q - 1)
    gcd, d, b = egcd(e, phi)
    # Keys:((pub),  (priv))
    return ((e, n), (d, n))


#Encode the message
def encode(key, p):
    e, n = key
    cipher = [pow(ord(char), e, n) for char in p]
    return cipher

if __name__ == "__main__":
    #generate 512 bit primes
    n_length = 512
    p = number.getPrime(n_length)
    q = number.getPrime(n_length)

    #generate the keys for the message
    msg_key = gen_keys(p, q)

    #print the public key (e and n)
    print("Public key:")
    print(msg_key[0])

    #I have the public key so I can recreate it with the input

    #encode the message
    givenKey  = (65537, 90105541557621252997171006589016894848807343069031985446900350291132345233374025023408859251351485987936325962797399526646150518803654057805921933202584795117827240704880053913075892922124467694186163111094636345380693310155758963732487621457199974518017674957316375530344820342239244223515293163966719748837)
    
    testList = []

    #lowercase
    for letter in ascii_lowercase:
        msg = letter

        msg_c=(encode(givenKey, msg))

        #print the encoded message
        print("letter:",letter)
        print("Encrypted message:")
        print(msg_c)

        testList.append(tuple((letter,msg_c)))
        #a_list.append(tuple((3, 4)))

    #capitals
    #get numbers
    for letter in ascii_lowercase:
        letter = letter.capitalize()
        msg = letter

        msg_c=(encode(givenKey, msg))

        #print the encoded message
        print("letter:",letter)
        print("Encrypted message:")
        print(msg_c)

        testList.append(tuple((letter,msg_c)))
        #a_list.append(tuple((3, 4)))

    for x in range(10):
        msg = str(x)

        msg_c=(encode(givenKey, msg))

        #print the encoded message
        print("number:",x)
        print("Encrypted message:")
        print(msg_c)

        testList.append(tuple((x,msg_c)))

    #not all inclusive but hopefully we don't need that
    specialList = string.printable
    #specialList = specialList+'"'
    #specialList = specialList+"'"
    #print string.printable
    for x in specialList:
        msg = str(x)

        msg_c=(encode(givenKey, msg))

        #print the encoded message
        print("special char:",x)
        print("Encrypted message:")
        print(msg_c)

        testList.append(tuple((x,msg_c)))

    myfile = open('xyz.txt', 'w')
    for t in testList:
        myfile.write(' '.join(str(s) for s in t) + '\n')

    myfile.close()

    #with open('encodedText.csv', newline='') as f:
    #    reader = csv.reader(f)
    #    data = list(reader)
        

    #    for column in data:
    #        for encryptedChar in column:
    #            #print(encryptedChar)
    #            encryptedChar = encryptedChar.strip()

    ##            for letter in ascii_lowercase:
      #              msg = letter
       #             msg_c=(encode(givenKey, msg))
                    #print("msg_c")
        #            print("letter:",letter)
         #           print(msg_c[0])
                    #print()
          #          print(encryptedChar)
            #        if msg_c[0] == encryptedChar:
           #             print(letter)

#So they give us the public key and, the encrypted message, looking at the encrypted message its a list of encrypted chars.
#So i just encrypted python's string.printable into a dictionary and looked up which encrypted chars matched