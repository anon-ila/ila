from seal import *
import numpy as np

class Backend():
    def __init__(self, scheme_ty):
        self.scheme_ty = scheme_ty

    def get_params_default(self):
        pass

    def get_coeff_modulus_list(self):
        pass

    def get_modulus_chain(self):
        pass

    def get_modulus_chain_highest_level(self):
        pass

    def get_params(self, omega):
        pass

    def get_plain_modulus(self):
        pass

    def plain_init(self, i):
        pass

    def vec_init(self, i, tag):
        pass

    def vec_mult(self, p1, p2, length):
        pass

    def vec_mult_plain(self, p1, p2):
        pass

    def vec_add(self, p1, p2):
        pass
    
    def vec_add_plain(self, p1, p2):
        pass

    def cipher_init(self, i):
        pass

    def cipher_add(self, p1, p2):
        pass

    def modswitch(self, c):
        pass
    
    def cipher_mult(self, ct1, ct2):
        pass
    
    def cipher_plain_mult(self, p1, p2):
        pass
    
    def cipher_plain_add(self, p1, p2):
        pass
    
    def plain_mult(self, p1, p2):
        raise RuntimeError('Unsupported: Plaintext multiplication')

    def plain_add(self, p1, p2):
        raise RuntimeError('Unsupported: Plaintext addition')
    
    
    def decrypt(self, c, length = None):
        pass
