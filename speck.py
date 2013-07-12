#!/usr/bin/env python

# This code is released under MIT license.

NUM_ROUNDS = {
    (32, 64): 22,
    (48, 72): 22,
    (48, 96): 23,
    (64, 96): 26,
    (64, 128): 27,
    (96, 96): 28,
    (96, 144): 29,
    (128, 128): 32,
    (128, 192): 33,
    (128, 256): 34,
}


class SPECK:
    """
    one of the two lightweight block ciphers designed by NSA
    this one is optimized for software implementation
    """
    def __init__(self, block_size, key_size, master_key=None):
        assert (block_size, key_size) in NUM_ROUNDS
        self.block_size = block_size
        self.key_size = key_size
        self.__num_rounds = NUM_ROUNDS[(block_size, key_size)]
        if block_size == 32 and key_size == 64:
            self.__alpha = 7
            self.__beta = 2
        else:
            self.__alpha = 8
            self.__beta = 3
        self.__dim = block_size / 2
        self.__mod = 1 << self.__dim
        if master_key is not None:
            self.change_key(master_key)

    def __rshift(self, x, i):
        assert i in (self.__alpha, self.__beta)
        return ((x << (self.__dim - i)) % self.__mod) | (x >> i)

    def __lshift(self, x, i):
        assert i in (self.__alpha, self.__beta)
        return ((x << i) % self.__mod) | (x >> (self.__dim - i))

    def __first_feistel(self, x, y):
        return y, (self.__rshift(x, self.__alpha) + y) % self.__mod

    def __second_feistel(self, x, y):
        return y, self.__lshift(x, self.__beta) ^ y

    # since the feistel used in this cipher is not in "the usual way"
    # it cannot be reused in decryption, and we have to write the inverse
    def __first_feistel_inv(self, x, y):
        return self.__lshift((y - x) % self.__mod, self.__alpha), x

    def __second_feistel_inv(self, x, y):
        return self.__rshift(x ^ y, self.__beta), x

    def change_key(self, master_key):
        assert 0 <= master_key < (1 << self.key_size)
        self.__round_key = [master_key % self.__mod]
        master_key >>= self.__dim
        llist = []
        for i in range(self.key_size / self.__dim - 1):
            llist.append(master_key % self.__mod)
            master_key >>= self.__dim
        for i in range(self.__num_rounds - 1):
            l, r = self.__first_feistel(llist[i], self.__round_key[i])
            r ^= i
            l, r = self.__second_feistel(l, r)
            llist.append(l)
            self.__round_key.append(r)

    def encrypt(self, plaintext):
        assert 0 <= plaintext < (1 << self.block_size)
        l = plaintext >> self.__dim
        r = plaintext % self.__mod
        for i in range(self.__num_rounds):
            l, r = self.__first_feistel(l, r)
            r ^= self.__round_key[i]
            l, r = self.__second_feistel(l, r)
        ciphertext = (l << self.__dim) | r
        assert 0 <= ciphertext < (1 << self.block_size)
        return ciphertext

    def decrypt(self, ciphertext):
        assert 0 <= ciphertext < (1 << self.block_size)
        l = ciphertext >> self.__dim
        r = ciphertext % self.__mod
        for i in range(self.__num_rounds - 1, -1, -1):
            l, r = self.__second_feistel_inv(l, r)
            r ^= self.__round_key[i]
            l, r = self.__first_feistel_inv(l, r)
        plaintext = (l << self.__dim) | r
        assert 0 <= plaintext < (1 << self.block_size)
        return plaintext


if __name__ == '__main__':
    test_vectors = (
        # block_size, key_size, key, plaintext, ciphertext
        (32, 64,
            0x1918111009080100,
            0x6574694c,
            0xa86842f2),
        (48, 72,
            0x1211100a0908020100,
            0x20796c6c6172,
            0xc049a5385adc),
        (48, 96,
            0x1a19181211100a0908020100,
            0x6d2073696874,
            0x735e10b6445d),
        (64, 96,
            0x131211100b0a090803020100,
            0x74614620736e6165,
            0x9f7952ec4175946c),
        (64, 128,
            0x1b1a1918131211100b0a090803020100,
            0x3b7265747475432d,
            0x8c6fa548454e028b),
        (96, 96,
            0x0d0c0b0a0908050403020100,
            0x65776f68202c656761737520,
            0x9e4d09ab717862bdde8f79aa),
        (96, 144,
            0x1514131211100d0c0b0a0908050403020100,
            0x656d6974206e69202c726576,
            0x2bf31072228a7ae440252ee6),
        (128, 128,
            0x0f0e0d0c0b0a09080706050403020100,
            0x6c617669757165207469206564616d20,
            0xa65d9851797832657860fedf5c570d18),
        (128, 192,
            0x17161514131211100f0e0d0c0b0a09080706050403020100,
            0x726148206665696843206f7420746e65,
            0x1be4cf3a13135566f9bc185de03c1886),
        (128, 256,
            0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100,
            0x65736f6874206e49202e72656e6f6f70,
            0x4109010405c0f53e4eeeb48d9c188f43)
    )

    for bsize, ksize, key, plain, cipher in test_vectors:
        my_speck = SPECK(bsize, ksize, key)
        encrypted = my_speck.encrypt(plain)
        assert encrypted == cipher
        for i in range(1000):
            encrypted = my_speck.encrypt(encrypted)
        for i in range(1000):
            encrypted = my_speck.decrypt(encrypted)
        decrypted = my_speck.decrypt(encrypted)
        assert decrypted == plain

    print 'All tests passed'
