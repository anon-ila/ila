from openfhe import *
from ila_backend import *
from math import log2

class OpenFHE(Backend):
    def __init__(self, scheme_ty, depth):
        # Sample Program: Step 1: Set CryptoContext
        self.scheme_ty = scheme_ty
        if self.scheme_ty == 1:
            self.params = CCParamsBGVRNS()
        elif self.scheme_ty == 2:
            self.params = CCParamsBFVRNS()
        else:
            # default is BGV
            self.params = CCParamsBGVRNS()
                
        self.params.SetMultiplicativeDepth(depth)
        self.params.SetPlaintextModulus(786433)
        self.params.SetMaxRelinSkDeg(3)
        
        if self.scheme_ty == 1:
            self.params.SetScalingTechnique(FIXEDMANUAL)
        #else:
        #    self.params.SetScalingTechnique(FIXEDAUTO)

        self.context = GenCryptoContext(self.params)
        # Enable features that you wish to use
        self.context.Enable(PKESchemeFeature.PKE)
        self.context.Enable(PKESchemeFeature.KEYSWITCH)
        self.context.Enable(PKESchemeFeature.LEVELEDSHE)
        self.context.Enable(PKESchemeFeature.ADVANCEDSHE)
        # Sample Program: Step 2: Key Generation

        # Generate a public/private key pair
        self.key_pair = self.context.KeyGen()

        # Generate the relinearization key
        self.context.EvalMultKeyGen(self.key_pair.secretKey)

        # Generate the rotation evaluation keys
        self.context.EvalRotateKeyGen(self.key_pair.secretKey, [1, 2, -1, -2])
        q = self.context.GetModulus()
        d = self.context.GetCyclotomicOrder()/2
        t = self.context.GetPlaintextModulus()
        print('==================================\n')
        print('q bits:', log2(q), "\n")
        print('Coefficient Modulus (q): %d\n' % q)
        print('Plaintext Modulus   (t): %d\n' % t)
        print('Poly mod degree     (d): %d\n' % d)
        print('==================================\n')

    def get_params_default(self):
        q = self.context.GetModulus()
        d = self.context.GetCyclotomicOrder()/2
        t = self.context.GetPlaintextModulus()
        # Deprecate: return 2
        return log2(q), q,  t, d


    def get_coeff_modulus_list(self):
        pass

    def get_modulus_chain(self):
        pass

    def get_modulus_chain_highest_level(self):
        # Mode is FlexibleautoExt; hence max levels = multiplicative depth + 2
        # https://openfhe.discourse.group/t/how-to-determing-the-number-of-towers/388/4
        d = self.params.GetMultiplicativeDepth()
        return d+2

    def get_params(self, omega):
        # q = self.context.GetModulus()
        d = self.context.GetCyclotomicOrder()/2
        t = self.context.GetPlaintextModulus()
        # Deprecate: return 2
        return 2, t, d

    def get_plain_modulus(self):
        pass

    def plain_init(self, i):
        vector_of_ints1 = [int(i)]
        p = self.context.MakePackedPlaintext(vector_of_ints1)
        return p

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
        vector_of_ints1 = [int(i), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        p = self.context.MakePackedPlaintext(vector_of_ints1)
        c = self.context.Encrypt(self.key_pair.publicKey, p)

        # no noise budget in openfhe
        return c, 0


    def cipher_add(self, c1, c2):
        c = self.context.EvalAdd(c1, c2)
        return c


    def modswitch(self, c):
        t = self.context.ModReduce(c)
        return t
    
    def cipher_mult(self, c1, c2):
        c = self.context.EvalMult(c1, c2)
        return c
    
    def cipher_plain_mult(self, p1, p2):
        p = self.context.EvalMult(p1, p2)
        return p

    def cipher_plain_add(self, p1, p2):
        p = self.context.EvalAdd(p1, p2)
        return p

    def plain_mult(self, p1, p2):
            raise RuntimeError('Unsupported: Plaintext multiplication')

    def plain_add(self, p1, p2):
            raise RuntimeError('Unsupported: Plaintext addition')
    
    # helper decrypt method
    def decrypt(self, c, length = None):
        p = self.context.Decrypt(c, self.key_pair.secretKey)
        # Openfhe does not have noise budget
        return p.GetPackedValue(), 0
    

        

    # def decrypt(ct):
    #     # Decrypt the result of multiplications
    #     res = self.context.Decrypt(ct, self.key_pair.secretKey)
    #     return res
