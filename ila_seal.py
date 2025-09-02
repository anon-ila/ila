import seal as Seal
from seal import *
import numpy as np
from ila_backend import *
import pickle

class Seal(Backend):
    def __init__(self, scheme_ty, depth):
        if scheme_ty == 'bgv':
            self.parms = EncryptionParameters (scheme_type.bgv)
        elif scheme_ty == 'bfv':
            self.parms = EncryptionParameters (scheme_type.bfv)
        else:
            #default is bgv
            self.parms = EncryptionParameters (scheme_type.bgv)
        poly_modulus_degree = 8192*4
        #poly_modulus_degree = 4096
        #poly_modulus_degree = 8192 * 4
        self.parms.set_poly_modulus_degree(poly_modulus_degree)
        #self.parms.set_coeff_modulus(CoeffModulus.BFVDefault(poly_modulus_degree))
        # self.parms.set_coeff_modulus(CoeffModulus.Create(poly_modulus_degree, [25, 25, 45, 45, 50]))
        #self.parms.set_coeff_modulus(CoeffModulus.Create(poly_modulus_degree, [25, 25, 40, 50, 55, 60, 60]))
        # [40,35,30,30,30,30, 25,25, 25, 25, 25,25,23,23, 40 ]
        #  [35, 30, 30, 30, 25, 25, 23, 25, 21, 25,21, 35]
        self.parms.set_coeff_modulus(CoeffModulus.Create(poly_modulus_degree, [60,60,60,55,55,50,50,50,50,45,45,45,40,40,35,35,30,30]))
        
        #self.parms.set_plain_modulus(PlainModulus.Batching(poly_modulus_degree, 20))
        self.parms.set_plain_modulus(PlainModulus.Batching(poly_modulus_degree, 20))
        self.context = SEALContext(self.parms)

        keygen = KeyGenerator(self.context)
        self.secret_key = keygen.secret_key()
        self.public_key = keygen.create_public_key()
        self.relin_keys = keygen.create_relin_keys()

        self.encryptor = Encryptor(self.context, self.public_key)
        self.evaluator = Evaluator(self.context)
        self.decryptor = Decryptor(self.context, self.secret_key)

        self.batch_encoder = BatchEncoder(self.context)
        self.slot_count = self.batch_encoder.slot_count()
        self.row_size = self.slot_count / 2
        print(f'Plaintext matrix row size: {self.row_size}')
        print(f'Plaintext modulus: {self.parms.plain_modulus().value()}')


    def get_params_default(self):
        L = self.get_modulus_chain_highest_level()
        logq, t, d  = self.get_params(L)
        #print('%d, %d, %d, %d\n' % (logq, t,  d, l))
        y = self.parms.coeff_modulus()
        q = 1
        for x in y:
            q = q * x.value()
        print('==================================\n')
        print('q bits:', logq, "\n")
        print('Coefficient Modulus (q): %d\n' % q)
        print('Plaintext Modulus   (t): %d\n' % t)
        print('Poly  Modulus       (d): %d\n' % d)
        print('==================================\n')
        return logq, q, t, d

    def get_coeff_modulus_list(self):
        y = self.parms.coeff_modulus()
        return y
    
    def get_modulus_chain(self):
        y = self.parms.coeff_modulus()
        qlist = [None]*(len(y))
        i = 0
        for x in y:
            qlist[i] =  x.value()
            i=i+1
        return qlist

    def get_modulus_chain_highest_level(self):
        y = self.parms.coeff_modulus()
        return len(y)

    def get_params(self, omega):
        logq = 0
        q = 1
        y = self.parms.coeff_modulus()
        y = y[:(omega+1)]
        for x in y:
            logq = logq + x.bit_count()
            # SEAL computes coeff_modulus, i.e. q, as product of a list of primes.
            q = q * x.value()

        t = self.parms.plain_modulus()
        d = self.parms.poly_modulus_degree() 
        return logq, t.value(), d #, q
    
    def get_plain_modulus(self):
        return self.parms.plain_modulus()
        
    # def plain_init(self, i):
    #     pod_matrix = [0] * self.slot_count
    #     pod_matrix[0] = i
    #     x_plain = self.batch_encoder.encode(pod_matrix)
    #     nz_coeff_count  = x_plain.nonzero_coeff_count() 
    #     return x_plain

    
    def plain_init(self, i):
        # encoding as constant polynomial
        pod_matrix = [0] * self.slot_count
        pod_matrix[0] = int(i)
        x_plain = self.batch_encoder.encode(pod_matrix)
        return x_plain
    
    def cipher_poly_init(self, s):
        x_plain = Plaintext(s)
        x_encrypted = self.encryptor.encrypt(x_plain)
        noise = self.decryptor.invariant_noise_budget(x_encrypted)
        return x_encrypted, noise
        
    def vec_init(self, i, tag, do_pack=False, psi=True):
        if psi and tag == 3:
            encrypted = []
            for val in i:
                pod_matrix = [0] * self.slot_count
                pod_matrix[0] = int(val)
                x_plain = self.batch_encoder.encode(pod_matrix)
                x_encrypted = self.encryptor.encrypt(x_plain)
                encrypted.append(x_encrypted)
            return encrypted , 0
        if psi and tag == 4:
            plain = []
            for val in i:
                pod_matrix = [0] * self.slot_count
                pod_matrix[0] = int(val)
                x_plain = self.batch_encoder.encode(pod_matrix)
                plain.append(x_plain)
            return plain, 0
        # non-iteratable vector
        if tag == 3 and do_pack:
            pod_matrix = [0] * self.slot_count
            for index, val in enumerate(i):
                pod_matrix[index] = int(val)
            x_plain = self.batch_encoder.encode(pod_matrix)
            x_encrypted = self.encryptor.encrypt(x_plain)
            #noise = self.decryptor.invariant_noise_budget(x_encrypted)
            return [x_encrypted], 0
        # non-iteratable vector
        elif tag == 4 and do_pack:
            pod_matrix = [0] * self.slot_count
            for index, val in enumerate(i):
                pod_matrix[index] = int(val)
            x_plain = self.batch_encoder.encode(pod_matrix)
            # noise = max([int(x.split("x")[0], 16) for x in x_plain.to_string().split('+')])
            return [x_plain], 0
        # iteratable cipher vector 
        elif tag == 3 and (not do_pack): 
            #open a file for data of a single column
            #print("lenght of cipher is:", len(i))
            #j = 0
            with open('encrypted.dat', 'wb') as f:
                for val in i:
                    pod_matrix = [0] * self.slot_count
                    pod_matrix[0] = int(val)
                    x_plain = self.batch_encoder.encode(pod_matrix)
                    x_encrypted = self.encryptor.encrypt(x_plain)
                    #print(x_encrypted)
                    pickle.dump(x_encrypted.to_string(),f)
                    #j += 1
            #print("j is",j)
            with open('encrypted.dat', 'rb') as p1:
                while True:
                    try:
                        operand1 = self.context.from_cipher_str(pickle.load(p1))
                        #print("operand is when created is", operand1)
                    except EOFError:
                        break
            return 'encrypted.dat', 0
        # iteratable plain vector 
        elif tag == 4 and (not do_pack):
            #with open('plain.dat', 'wb') as f:
                t = []
                for val in i:
                    pod_matrix = [0] * self.slot_count
                    pod_matrix[0] = int(val)
                    x_plain = self.batch_encoder.encode(pod_matrix)
                    t.append(x_plain)
                    #pickle.dump(x_plain.to_string(), f)
                #return 'plain.dat', 0
                #print(" Plain text lenght is:", len(t))
                return t,0
                
    def vec_mult(self, p1, p2):
        t_lin = []
        for index, val in enumerate(p1):
            t = self.evaluator.multiply(val, p2[index])
            t_lin.append(self.evaluator.relinearize(t, self.relin_keys))
        return t_lin
    
    def vec_plain_mult(self, p1_id, p2_id):
        #print("@vec_plain_mult with array")
        i = 0
        with open(p1_id, "rb") as p1:
            with open('mul_result.dat', 'wb') as f:
                while True:
                    #with open(p2_id, "r") as p2:
                    try:
                        operand1 = self.context.from_cipher_str(pickle.load(p1))
                        operand2 = p2_id[i]
                    except EOFError:
                        return 'mul_result.dat'
                    #operand2 = p2_id[i]
                    i += 1
                    t = self.evaluator.multiply_plain(operand1, operand2)
                    f.write(pickle.dumps(t.to_string()))

    
    def vec_add(self, p1, p2):
        t = []
        for index, val in enumerate(p1):
            t.append(self.evaluator.add(val, p2[index]))
        return t
    
    def vec_plain_add(self, p1, p2):
        t = []
        for index, val in enumerate(p1):
            t.append(self.evaluator.add_plain(val, p2[index]))
        return t
    
    def cipher_mat_mult(self, p1, p2):
        t = [ [0 for x in range(len(p1))] for y in range(len(p2[0]))]
        for i in range (len(p1)):
            for j in range(len(p2[0])):
                for k in range(len(p2)):
                    temp = self.evaluator.multiply(p1[i][k], p2[k][j])
                    t[i][j] = self.evaluator.relinearize(temp, self.relin_keys)
        return t

        
    def cipher_init(self, i):
        pod_matrix = [0] * self.slot_count
        # Coefficient cannot be floats.
        # Convert to int just incase if i happens to be a float.
        pod_matrix[0] = int(i)
        x_plain = self.batch_encoder.encode(pod_matrix)
        # x_plain = Plaintext(str(int(i)))
        x_encrypted = self.encryptor.encrypt(x_plain)
        noise = self.decryptor.invariant_noise_budget(x_encrypted)
        return x_encrypted, noise
        
    def cipher_mult(self, p1, p2):
        t = self.evaluator.multiply(p1, p2)
        t_lin = self.evaluator.relinearize(t, self.relin_keys)
        # Print the decrypted value
        # t_decrypted = self.decryptor.decrypt(t)
        # t_decoded = self.batch_encoder.decode(t_decrypted)
        # print(f'Decrypted cipher text: {t_decrypted}')
        # print_vector(t_decoded)
        # print('-'*50)
        
        return t_lin

    def cipher_add(self, p1, p2):
        t = self.evaluator.add(p1, p2)
        # Print the decrypted value
        # t_decrypted = self.decryptor.decrypt(t)
        # t_decoded = self.batch_encoder.decode(t_decrypted)
        # print(f'Decrypted cipher text: {t_decrypted}')
        # print_vector(t_decoded)
        # print('-'*50)
        return t

    def modswitch(self, c):
         t = self.evaluator.mod_switch_to_next_inplace(c)
         return t
    
    
    def cipher_plain_mult(self, p1, p2):
        t = self.evaluator.multiply_plain(p1, p2)
        return t

    def cipher_plain_add(self, p1, p2):
        t = self.evaluator.add_plain(p1, p2)
        return t

    def plain_mult(self, p1, p2):
            raise RuntimeError('Unsupported: Plaintext multiplication')

    def plain_add(self, p1, p2):
            raise RuntimeError('Unsupported: Plaintext addition')

    # helper decrypt method
    def decrypt(self, c, length = None):
        noise = self.decryptor.invariant_noise_budget(c)
        t_decrypted = self.decryptor.decrypt(c)
        t_decoded = self.batch_encoder.decode(t_decrypted)
        if length == None:
            return int(t_decoded[0]), noise
        return t_decoded[0:length], noise

    def vec_decrypt(self, p1, size):
        t = np.zeros((len(p1), len(p1[0])), dtype=int)
        noise = np.zeros((len(p1), len(p1[0])), dtype=int)
        for i in range(len(p1)):
            for j in range(len(p1[0])):
                noise[i][j] = self.decryptor.invariant_noise_budget(p1[i][j])
                t_decrypted = self.decryptor.decrypt(p1[i][j])
                t[i][j] = self.batch_encoder.decode(t_decrypted)[0]
        return t, noise
    
    def vector_decrypt(self, p1, psi=True):
        t = []
        noise = []
        if psi:
            for i in p1:
                t.append(self.batch_encoder.decode(self.decryptor.decrypt(i))[0])
                noise.append(self.decryptor.invariant_noise_budget(i))
            return t, noise
        with open(p1, 'rb') as p1_line:
            while True:
                    try:
                        temp = self.context.from_cipher_str(pickle.load(p1_line))
                        t.append(self.batch_encoder.decode(self.decryptor.decrypt(temp))[0])
                        noise.append(self.decryptor.invariant_noise_budget(temp))
                    except EOFError:
                        return t, noise

        
    
    def vector_decode(self, p):
        t = []
        for i in p:
            t.append(self.batch_encoder.decode(i)[0])
        #with open(p, "rb") as p_line:
            #while True:
                    #try:
                        #temp = self.context.from_plain_str(pickle.load(p_line))
                        # t.append(self.batch_encoder.decode(temp)[0])
                    #except EOFError:
                    #    break
        #print("@ leaving vec_decode")
        return t
        


    # helper decode method
    def decode(self, p, length = None):
        t_decoded = self.batch_encoder.decode(p)
        if length == None:
            return int(t_decoded[0])
        return t_decoded[:length]
        

def print_vector(vector):
    print('[ ', end='')
    for i in range(0, 8):
        print(vector[i], end=', ')
    print('... ]')
