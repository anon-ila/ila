from openfhe import *
from ila_backend import *
from math import log2

class OpenFHE(Backend):
    def __init__(self, scheme_ty):
        # Sample Program: Step 1: Set CryptoContext
        self.scheme_ty = scheme_ty
        if self.scheme_ty == 1:
            self.params = CCParamsBGVRNS()
        elif self.scheme_ty == 2:
            self.params = CCParamsBFVRNS()
        else:
            # default is BGV
            self.params = CCParamsBGVRNS()
                
        # self.params.SetScalingTechnique(FIXEDMANUAL)
        self.params.SetMultiplicativeDepth(3)
        self.params.SetEvalAddCount(3)
        self.params.SetPlaintextModulus(786433)
        self.params.SetMaxRelinSkDeg(3)
        self.params.SetScalingTechnique(FIXEDMANUAL)

        self.context = GenCryptoContext(self.params)
        # Enable features that you wish to use
        self.context.Enable(PKESchemeFeature.PKE)
        self.context.Enable(PKESchemeFeature.KEYSWITCH)
        self.context.Enable(PKESchemeFeature.LEVELEDSHE)

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
        return 2, q,  t, d


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
        return p, 0
        
    def cipher_mult_test(self):
         # First plaintext vector is encoded
         vector_of_ints1 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
         plaintext1 = self.context.MakePackedPlaintext(vector_of_ints1)

         # Second plaintext vector is encoded
         vector_of_ints2 = [3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12]
         plaintext2 = self.context.MakePackedPlaintext(vector_of_ints2)

         # Third plaintext vector is encoded
         vector_of_ints3 = [1, 2, 5, 2, 5, 6, 7, 8, 9, 10, 11, 12]
         plaintext3 = self.context.MakePackedPlaintext(vector_of_ints3)

         # The encoded vectors are encrypted
         ciphertext1 = self.context.Encrypt(self.key_pair.publicKey, plaintext1)
         ciphertext2 = self.context.Encrypt(self.key_pair.publicKey, plaintext2)
         ciphertext3 = self.context.Encrypt(self.key_pair.publicKey, plaintext3)

         #  Sample Program: Step 4: Evaluation

         # Homomorphic additions
         ciphertext_add12 = self.context.EvalAdd(ciphertext1, ciphertext2)
         ciphertext_add_result = self.context.EvalAdd(ciphertext_add12, ciphertext3)

         # Homomorphic Multiplication
         ciphertext_mult12 = self.context.EvalMult(ciphertext1, ciphertext2)
         ciphertext_mult_result = self.context.EvalMult(ciphertext_mult12, ciphertext3)

         # Homomorphic Rotations
         ciphertext_rot1 = self.context.EvalRotate(ciphertext1, 1)
         ciphertext_rot2 = self.context.EvalRotate(ciphertext1, 2)
         ciphertext_rot3 = self.context.EvalRotate(ciphertext1, -1)
         ciphertext_rot4 = self.context.EvalRotate(ciphertext1, -2)

             # Decrypt the result of additions
         plaintext_add_result = self.context.Decrypt(
             ciphertext_add_result, self.key_pair.secretKey
         )

         # Decrypt the result of multiplications
         plaintext_mult_result = self.context.Decrypt(
             ciphertext_mult_result, self.key_pair.secretKey
         )

         # Decrypt the result of rotations
         plaintextRot1 = self.context.Decrypt(ciphertext_rot1, self.key_pair.secretKey)
         plaintextRot2 = self.context.Decrypt(ciphertext_rot2, self.key_pair.secretKey)
         plaintextRot3 = self.context.Decrypt(ciphertext_rot3, self.key_pair.secretKey)
         plaintextRot4 = self.context.Decrypt(ciphertext_rot4, self.key_pair.secretKey)

         plaintextRot1.SetLength(len(vector_of_ints1))
         plaintextRot2.SetLength(len(vector_of_ints1))
         plaintextRot3.SetLength(len(vector_of_ints1))
         plaintextRot4.SetLength(len(vector_of_ints1))

         print("Plaintext #1: " + str(plaintext1))
         print("Plaintext #2: " + str(plaintext2))
         print("Plaintext #3: " + str(plaintext3))

         # Output Results
         print("\nResults of homomorphic computations")
         print("#1 + #2 + #3 = " + str(plaintext_add_result))
         print("#1 * #2 * #3 = " + str(plaintext_mult_result))
         print("Left rotation of #1 by 1 = " + str(plaintextRot1))
         print("Left rotation of #1 by 2 = " + str(plaintextRot2))
         print("Right rotation of #1 by 1 = " + str(plaintextRot3))
         print("Right rotation of #1 by 2 = " + str(plaintextRot4))

        

    # def decrypt(ct):
    #     # Decrypt the result of multiplications
    #     res = self.context.Decrypt(ct, self.key_pair.secretKey)
    #     return res
