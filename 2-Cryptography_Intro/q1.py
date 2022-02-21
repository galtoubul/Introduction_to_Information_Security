import itertools
import re
import os

class RepeatedKeyCipher:

    def __init__(self, key: bytes = bytes([0, 0, 0, 0, 0])):
        """Initializes the object with a list of integers between 0 and 255."""
        # WARNING: DON'T EDIT THIS FUNCTION!
        self.key = list(key)

    def encrypt(self, plaintext: str) -> bytes:
        """Encrypts a given plaintext string and returns the ciphertext."""
        # Xoring each byte of the key (in a cycle in case len(key) < len(plaintext))
        # with the proper plaintext bytes
        return bytes([k ^ p for k, p in zip(itertools.cycle(self.key), plaintext.encode('latin-1'))])

    def decrypt(self, ciphertext: bytes) -> str:
        """Decrypts a given ciphertext string and returns the plaintext."""
        # Since xor is a "cyclic op" ((c = p xor k) xor k = p) then we can use encrypt function
        return (self.encrypt(ciphertext.decode('latin-1'))).decode('latin-1')

letters_prob = {"a":0.082 , "b":0.015 , "c":0.028 , "d":0.043 , "e":0.13 , "f":0.022 , "g":0.02 , "h":0.061 , "i":0.07 , "j":0.0015 ,
                "k":0.0077 , "l":0.04 , "m":0.024 , "n":0.067 , "o":0.075 , "p":0.019 , "q":0.00095 , "r":0.06 , "s":0.063 , "t":0.091 ,
                "u":0.028 , "v":0.0098 , "w":0.024 , "x":0.0015 , "y":0.02 , "z":0.00074, " ":0.05 }

class BreakerAssistant:

    # 3000 English common words file
    # Source: https://www.ef.com/wwen/english-resources/english-vocabulary/top-3000-words/
    path_to_py = os.path.abspath(__file__)
    path_to_dir = os.path.dirname(path_to_py)
    path_to_file = os.path.join(path_to_dir, "common_words.txt")
    f = open(path_to_file, "r")
    words = re.sub("[^\w]", " ", f.read()).split()  

    def plaintext_score(self, plaintext: str) -> float:
        """Scores a candidate plaintext string, higher means more likely."""
        score = 0
        for word in re.split("\s+|[,.:!]", plaintext):
            # Ignore whitespaces
            if not word.strip():
                continue

            word = word.lower()
            if word.encode('latin-1').isalpha():

                # If it is a one letter word it should be a or i
                if len(word) == 1:
                    if word not in ["i", "a"]:
                        score -= 2
                    else:
                        score += letters_prob[word]

                # If it is more than one letter is should be a proper word 
                elif word in self.words:
                    score += len(word)
                else:
                    score -= len(word)
            
            # Punish a non English word
            else:
                score -= len(word) * 0.5
        return score        

    def brute_force(self, cipher_text: bytes, key_length: int) -> str:
        """Breaks a Repeated Key Cipher by brute-forcing all keys."""
        keys = itertools.product(range(0, 256), repeat = key_length)
        max_score = 0
        max_scored_text = ""
        for key in keys:
            k = RepeatedKeyCipher(bytes(key))
            p = k.decrypt(cipher_text)
            score = self.plaintext_score(p)
            if score > max_score:
                max_scored_text = p
                max_score = score
        return max_scored_text

    def brute_force_one_byte(self, sub_cipher) -> int:
        """ Crack one byte og the key based on letters probability """
        max_score = 0
        for i in range(256):
            curr_score = 0
            for c in sub_cipher:
                p = c ^ i
                curr_score += letters_prob.get(chr(p).lower(), 0)
            if curr_score > max_score:
                max_score = curr_score
                max_scored_key = i
        return max_scored_key

    def smarter_break(self, cipher_text: bytes, key_length: int) -> str:
        """Breaks a Repeated Key Cipher any way you like."""

        # divide cipher_text into chunks at size key_length
        sub_ciphers = []
        for i in range(key_length):
            sub_cipher = []
            for j in range(i, len(cipher_text), key_length):
                sub_cipher.append(cipher_text[j])
            sub_ciphers.append(sub_cipher)

        # break each key byte
        key = bytearray()
        for sub_cipher in sub_ciphers:
            key.append(self.brute_force_one_byte(sub_cipher))

        # decrypt the cipher in accordance to the key
        rkc = RepeatedKeyCipher(key)
        return rkc.decrypt(cipher_text)

        