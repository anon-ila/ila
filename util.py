import json
#import numpy as np
import decimal as dp

class TypecheckError(Exception):
    def __init__(self, message, error_code):            
        # Call the base class constructor with the parameters it needs
        # super().__init__()
        self.message = message
        # Now for your custom code...
        self.error_code = error_code

class MSInferError(Exception):
    def __init__(self, stmt, error_code, backend):            
        self.stmt = stmt
        self.error_code = error_code
        self.backend = backend
  

def is_cipher_type(ty):
    if "cipher" in ty:
        return True
    else:
        return False

def is_plain_type(ty):
    if "plain" in ty:
        return True
    else:
        return False

def get_level(t, gamma, backend):
    ty = t.typecheck(gamma)
    if is_cipher_type(ty):
        _, _, _, om = get_cipher_type_attributes(ty)
        return om
    else:
        return backend.get_modulus_chain_highest_level()
    

def get_plain_type_attributes(t, scheme=None):
    _, inf, sup, noise = t.split(" ")
    inf = inf[1:-1]
    sup = sup[:-1]
    noise = noise[:-1]
    if inf != 'NaN':
        inf = float(inf)
    if sup != 'NaN':
        sup = float(sup)
    return inf, sup, dp.Decimal(noise), -1

def is_subtype(t1, t2):
   if "cipher" in t1 and "cipher" in t2:
       # compare inf, sup and epsilon
       inf1, sup1, eps1, om1 = get_cipher_type_attributes(t1)
       inf2, sup2, eps2, om2 = get_cipher_type_attributes(t2)
       print("values for t1 are:", inf1, sup1, eps1, om1)
       print("values for t2 are:", inf2, sup2, eps2, om2)
       #    inf2 < inf1       sup1 < sup2    eps1 < eps2
       #  ----------------------------------------------------------  
       #   cipher (inf1, sup1, eps1) < cipher (inf2, sup2, eps2)
       #
       if func_correct:
           if (inf2 <= inf1) and (sup1 <= sup2) and (eps1 <= eps2) and (om1 == om2):
               return True
           else:
               if inf2 > inf1:
                   code = 11
               elif sup1 > sup2:
                   code = 12
               elif eps1 > eps2:
                   code = 13
               else:
                   code = 15
               raise TypecheckError('Subtype error', code)
       else:
           if (eps1 <= eps2):
               return True
           else:
               code = 15
               raise TypecheckError('Subtype error', code)
   elif "plain" in t1 and "plain" in t2:
       # compare val and delta
       val1, delta1 = get_plain_type_attributes(t1)
       val2, delta2 = get_plain_type_attributes(t2)
       if (val1 <= val2) and (delta1 <= delta2):
           return True
       else:
           code = 16
           raise TypecheckError('Subtype error', code)

   #other cases
   elif t1 == t2:
       return True
   else:
       return False

def get_vec_type(t):
   # vec;cipher;lenght;type_list
    lst = t.split(";")
    if len(lst) == 5:
        return lst[0], lst[1], (int(lst[2]), int(lst[3])), json.loads(lst[4])
    return lst[0], lst[1], int(lst[2]), json.loads(lst[3])

def get_cipher_type_attributes(t):
    split_list = t.split(" ")
    inf = split_list[1][1:-1]
    sup = split_list[2][:-1]
    eps = split_list[3][:-1]
    if inf != 'NaN':
        inf = float(inf)
    if sup != 'NaN':
        sup = float(sup)
    #if len(split_list) == 5:
    return inf, sup, dp.Decimal(eps), int(split_list[4][:-1])
    #return inf, sup, np.longdouble(eps)
