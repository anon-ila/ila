# sorts ::= {ciper, msg, plain, vec s}
# n \in Nat
# types ::= cipher \alpha_cipher | plain \alpha_{plain} | msg \alpha_{msg} | vec s \alpha_{vec s}
# 
#            \alpha = (\alpha_i) |\alpha| = n    \Gamma \vdash e_i : cipher \alpha_i
#----------------------------------------------------------------------------------------------------
#                       \Gamma \vdash [e_1 ... e_n] : vec cipher \alpha_{vec cipher}


#   op : s_i -> vec cipher   \forall i \Gamma \vdash e_i : \tau_i    sort(t_i) = s_i     [[op]]_{bnd}^pp(|tau_i|) = \alpha_{vec n}
# --------------------------------------------------------------------------------------------------------------------------------------
#                       \Gamma \vdash op(e_i) : vec cipher \alpha_{vec cipher}
#
# 
#   forall i : |tau_i| = \alpha_i   /\  |\alpha_i| = n  \alpha_i = (\alpha_i^(j))_{j=1}^n    \alpha_{vec n} = ([[op]]_{bnd}^pp((\alpha_i^(j)))_i          
# -------------------------------------------------------------------------------------------------------------------------------------------------
#                                   [[op]]_{bnd}^pp(|tau_i|) = \alpha_{vec n}
#
# The last premise is defined by definition of op.
#
#
#
#

from numpy import double
from equality import *

from ila_backend import *
from ila_seal import *
from ila_openfhe import *
from ila_tfhers import *
from  ila_bgvast import *
from  ila_bfvast import *
from  ila_tfheast import *

import math
import sys
import numpy as np
import gc
import json


func_correct = True
perf = True

class Statement(Equality):
    pass

class IlaExp(Equality):
    pass

class Aexp(IlaExp):
    pass

class Bexp(IlaExp):
    pass

class Pexp(IlaExp):
    pass

class Vexp(IlaExp):
    pass

class Type(Equality):
    pass

class Declare_Type(Type):
    def __init__(self, name, ty):
        self.name = name
        self.ty = ty

    def __repr__(self):
        return 'Declare_Type(%s, %s)' % (self.name, self.ty)

    def eval(self, gamma):
        gamma[self.name] = str(self.ty)


class CompoundDecl(Type):
    def __init__(self, first, second):
        self.first = first
        self.second = second

    def __repr__(self):
        return 'CompoundDecl(%s, %s)' % (self.first, self.second)

    def eval(self, gamma):
        self.first.eval(gamma)
        self.second.eval(gamma)

class AssignStatement(Statement):
    def __init__(self, name, exp, scheme_ty):
        # self.name := self.exp
        self.name = name
        self.exp = exp
        self.bgv = None
        self.bfv = None
        self.tfhe = None
        self.scheme_ty =  int(scheme_ty)
        if (self.scheme_ty == 1):
            self.bgv = BGVAssignStatement(name, exp)
        elif (self.scheme_ty == 2):
            self.bfv = BFVAssignStatement(name, exp)
        elif (self.scheme_ty == 3):
            self.tfhe = TFHEAssignStatement(name, exp)
        
    def __repr__(self):
        if (self.scheme_ty == 1):
            return self.bgv.__repr__()
        elif (self.scheme_ty == 2):
            return self.bfv.__repr__()        
        elif (self.scheme_ty == 3):
            return self.tfhe.__repr__()


    def compile(self):
        s_name = self.name
        s_exp = self.exp.compile()
        s = "let mut " + s_name + " = " + s_exp + ";\n"
        return s
    
    def eval(self, env):
        if (self.scheme_ty == 1):
            self.bgv.eval(env)
        elif (self.scheme_ty == 2):
            self.bfv.eval(env)

        
    def is_sub_type (self, type_1, type_2):
        v = False
        if (self.scheme_ty == 1):
            v = self.bgv.is_sub_type(type_1, type_2)
        elif (self.scheme_ty == 2):
            v = self.bfv.is_sub_type(type_1, type_2)
        elif (self.scheme_ty == 3):
            v = self.tfhe.is_sub_type(type_1, type_2)
        return v
                
    def typeinfer(self, gamma, logq, q,t,d):
        error, gamma_new = None, None
        if (self.scheme_ty == 1):
            (error, gamma_new) = self.bgv.typeinfer(gamma, logq, q, t, d)
        if (self.scheme_ty == 2):
            (error, gamma_new) = self.bfv.typeinfer(gamma, logq, q, t, d)
        if (self.scheme_ty == 3):
            (error, gamma_new) = self.tfhe.typeinfer(gamma, logq, q, t, d)
        return error, gamma_new

    def typecheck(self, gamma):
        v = False
        if (self.scheme_ty == 1):
            v = self.bgv.typecheck(gamma)
        elif (self.scheme_ty == 2):
            v = self.bfv.typecheck(gamma)
        elif (self.scheme_ty == 3):
            v = self.tfhe.typecheck(gamma)
        return v
        
    def typecheck_relaxed(self, gamma):
        v = False
        if (self.scheme_ty == 1):
            v = self.bgv.typecheck_relaxed(gamma)
        elif (self.scheme_ty == 2):
            v = self.bfv.typecheck_relaxed(gamma)
        elif (self.scheme_ty == 3):
            v = self.tfhe.typecheck_relaxed(gamma)
        return v
        
    def ms_infer(self, gamma_rel, gamma, om):
        if (self.scheme_ty == 1):
            name, newexp, c, gamma = self.bgv.ms_infer(gamma_rel, gamma, om)
        else:
            raise "Mod Switch is not supported for BFV and TFHE"
        return AssignStatement(name, newexp, self.scheme_ty), c, gamma
        
    def levelizer(self, gamma):
        if (self.scheme_ty == 1):
            name, newexp = self.bgv.levelizer(gamma)
        else:
            raise "Mod Switch is not supported for BFV and TFHE"
        return AssignStatement(name, newexp, self.scheme_ty)
        
    def get_modswitch_depth(self, gamma):
        if (self.scheme_ty == 1):
            return self.bgv.get_modswitch_depth(gamma)
        else:
            raise "Mod Switch is not supported for BFV and TFHE"
        
        
class CompoundStatement(Statement):
    def __init__(self, first, second):
        self.first = first
        self.second = second

    def __repr__(self):
        return '%s; \n %s' % (self.first, self.second)

    def compile(self):
        sfirst = self.first.compile()
        ssecond = self.second.compile()
        return sfirst + ssecond
    
    def eval(self, env):
        self.first.eval(env)
        self.second.eval(env)
        
    """ def typecheck(self, gamma):
        if self.first.typecheck(gamma):
            if self.second.typecheck(gamma):
                return True
        else:
            return False """
    
    def typeinfer(self,gamma, logq, q, t, d):
        try: 
            error, gamma1 = self.first.typeinfer(gamma,logq, q,t,d)
        except Exception as e:
            #print (e.message)
            raise e #TypecheckError(e.message, e.error_code)
        if error != "":
            try:
                gamma2 = self.second.typeinfer(gamma1,logq,q,t,d)[1] 
                return(error,gamma2)
            except Exception as e:
               #print (e.message)
               raise e #TypecheckError(e.message, e.error_code)
        else:  
            try:
                error,gamma2 = self.second.typeinfer(gamma1,logq,q,t,d)
                return(error,gamma2)
            except Exception as e:
                raise e #TypecheckError(e.message, e.error_code)

    def typecheck(self, gamma):
        status = False
        try:
            status=self.first.typecheck(gamma)
        except Exception as e1:
            raise e1
        if status:
            try:
                if self.second.typecheck(gamma):
                        return True
            except Exception as e:
                raise e

    def typecheck_relaxed(self, gamma):
        if self.first.typecheck_relaxed(gamma):
            if self.second.typecheck_relaxed(gamma):
                return True
        else:
            return False

    def ms_infer(self, gamma_rel, gamma, om):
        c1hat = self.first
        c2hat = self.second
        changed = False
        c1hat, changed, newgamma = self.first.ms_infer(gamma_rel, gamma, om)
        secondgamma = newgamma
        if changed:
            c1hat = c1hat.levelizer(newgamma)
        else:
            c2hat, changed, secondgamma = self.second.ms_infer(gamma_rel, newgamma, om)
        return CompoundStatement(c1hat, c2hat), changed, secondgamma

    def levelizer(self, gamma):
        c1hat = self.first.levelizer(gamma)
        c2hat = self.second.levelizer(gamma)
        return CompoundStatement(c1hat, c2hat)
    
    def get_modswitch_depth(self, gamma):
        om1 = self.first.get_modswitch_depth(gamma)
        om2 = self.second.get_modswitch_depth(gamma)
        if om1 == 'NaN':
            return om2
        elif om2 is None:
            return om1
        else:
            if om1 > om2:
                return om1
            else:
                return om2
        
class IfStatement(Statement):
    def __init__(self, condition, true_stmt, false_stmt):
        self.condition = condition
        self.true_stmt = true_stmt
        self.false_stmt = false_stmt

    def __repr__(self):
        return 'IfStatement(%s, %s, %s)' % (self.condition, self.true_stmt, self.false_stmt)
    
    def compile(self):
        pass

    def eval(self, env):
        condition_value = self.condition.eval(env)
        if condition_value:
            self.true_stmt.eval(env)
        else:
            if self.false_stmt:
                self.false_stmt.eval(env)
                
    def typeinfer(self, gamma, logq, coeff_mod,plain_mod,d):
        try:
            t = self.condition.typecheck(gamma)
        except Exception as e2:
            raise e2
        if t == 'bool':
            try:
                err,gamma1 = self.true_stmt.typeinfer(gamma, logq, coeff_mod,plain_mod,d)
                if err != "":
                    _ ,gamma2 = self.false_stmt.typeinfer(gamma, logq, coeff_mod ,plain_mod,d)
                else:
                    err,gamma2 = self.false_stmt.typeinfer(gamma, logq, coeff_mod ,plain_mod,d)
                common_keys = set()
                for i in gamma1.keys():
                    if i in gamma2.keys():
                        common_keys.add(i)
                ret_gamma = {}
                for i in common_keys:
                    if gamma1[i][2] >= gamma2[i][2]:
                        ret_gamma[i] = gamma1[i]
                    else:
                        ret_gamma[i] = gamma2[i]
                for key in gamma1.keys():
                    if key not in common_keys:
                        ret_gamma[key] = gamma1[key]
                for key in gamma2.keys():
                    if key not in common_keys:
                        ret_gamma[key] = gamma2[key]
                return err, ret_gamma
            except Exception as e1:
                raise e1
        else:
            raise TypecheckError('Conditional expression %s has non-boolean type.\n' % self.condition, 1336)


    def typecheck(self, gamma):
        try:
            t = self.condition.typecheck(gamma)
        except Exception as e2:
            raise e2
        if t == 'bool':
            try:
                if self.true_stmt.typecheck(gamma) and self.false_stmt.typecheck(gamma):
                    return True
            except Exception as e1:
                raise e1
        else:
            raise TypecheckError('Conditional expression %s has non-boolean type.\n' % self.condition, 1351)

    def typecheck_relaxed(self, gamma):
        t = self.condition.typecheck_relaxed(gamma)
        if t == 'bool':
            if self.true_stmt.typecheck_relaxed(gamma) and self.false_stmt.typecheck_relaxed(gamma):
                return True
            else:
                return False
        else:
            return False
        
    def ms_infer(self, gamma_rel, gamma, insert):
        return self, False, gamma

    def levelizer(self, gamma):
        return self

class WhileStatement(Statement):
    def __init__(self, condition, body):
        self.condition = condition
        self.body = body
 
    def __repr__(self):
        return 'WhileStatement(%s, %s)' % (self.condition, self.body)

    def typeinfer(self,gamma, logq, q,t,d):
        i = 1
        err = ""
        if not isinstance(self.condition, IntAexp):
            # raise Error
            raise TypecheckError("While loop may not terminate", 20)
        while i <= n.v:
            try:
                #print(gamma)
                error,gamma = self.body.typeinfer(gamma, logq, q,t,d)
                #print("\n After type infer", gamma)
            except Exception as e:
                #print("Depth is:",i)
                raise TypecheckError(e.message, e.error_code)
            if error:
                err = error
            i += 1
        return(err, gamma)

    def compile(self):
        pass
    
    def eval(self, env):
        # condition is either a value or a variable
        n = self.condition.eval(env)
        if n.v >= 0:
            self.body.eval(env)
            # decrement loop
            n.v = n.v-1
            newc = self.condition
            # update env if necessary
            if isinstance(n, IntAexp):
                newc = Value(n.v, 0)
            else:
                env[self.condition.name] = Value(n.v, 0)
                
            # call while again
            newwhile = WhileStatement(newc, self.body)
            newwhile.eval(env)
        # while i <= self.condition:
        #     self.body.eval(env)
        #     i += 1
        # return(env)

    def typecheck(self, gamma):
        i = 1
        while i <= self.condition:
            try:
                 self.body.typecheck(gamma)
            except Exception as e2:
                raise e2
            i += 1

    def typecheck_relaxed(self, gamma):
        i = 1
        while i <= self.condition:
            try:
                 self.body.typecheck(gamma)
            except Exception as e2:
                raise e2
            i += 1
        
    def ms_infer(self, gamma_rel, gamma, insert):
        i = 1
        while i <= self.condition:
            try:
                 self.body.ms_infer(gamma_rel, gamma, insert)
            except Exception as e2:
                raise e2
            i += 1
        
    
 

class IlaType(Type):
    def __init__(self, t):
        self.ty = t
    def __repr__(self):
        return '%s' % self.ty

    
class IlaFloat(IlaType):
    def __init__(self):
        self.ty = 'float'
    def __repr__(self):
        return '%s' % self.ty
    
    
class IlaInteger(IlaType):
    def __init__(self):
        self.ty = 'integer'
    def __repr__(self):
        return '%s' % self.ty
    
class VecType(IlaType):
    def __init__(self, tyname, sort, tylist, tag, size=None, length = 0):
        self.ty = tyname
        self.length = int(length)
        self.tylist = tylist
        self.sort = sort
        self.size = size
        self.tag = tag
        if (tag == 5 or tag == 6) and tylist == []:
            self.tylist = [([(float('NaN'),float('NaN'),0,0)]*size[1]) for i in range(size[0])]
    def __repr__(self):
        if self.tag == 5 or self.tag == 6:
            return '%s;%s;%d;%d;%s' % (self.ty, self.sort, int(self.size[0]), int(self.size[1]) ,json.dumps(self.tylist))
        return '%s;%s;%d;%s' % (self.ty, self.sort, self.length ,json.dumps(self.tylist))



class CipherType(IlaType):
    def __init__(self, tyname, inf, sup, eps, om, scheme_ty):
        self.bgv = None
        self.bfv = None
        self.tfhe = None
        self.scheme_ty =  int(scheme_ty)
        if (self.scheme_ty == 1):
            self.bgv = BGVCipherType(tyname, inf, sup, eps, om)
        elif (self.scheme_ty == 2):
            self.bfv = BFVCipherType(tyname, inf, sup, eps)
        elif (self.scheme_ty == 3):
            self.tfhe = TFHECipherType(tyname, inf, sup, eps)
        
    def __repr__(self):
        if (self.scheme_ty == 1):
            return self.bgv.__repr__()
        elif (self.scheme_ty == 2):
            return self.bfv.__repr__()
        elif (self.scheme_ty == 3):
            return self.tfhe.__repr__()

class PlainType(IlaType):
    def __init__(self, tyname, inf, sup, eps, scheme_ty):
        self.bgv = None
        self.bfv = None
        self.tfhe = None
        self.scheme_ty = int(scheme_ty)
        if (self.scheme_ty == 1):
            self.bgv = BGVPlainType(tyname, inf, sup, eps)
        elif (self.scheme_ty == 2):
            self.bfv = BFVPlainType(tyname, inf, sup, eps)
        elif (self.scheme_ty == 3):
            self.tfhe = TFHEPlainType(tyname, inf, sup, eps)
        
    def __repr__(self):
        if (self.scheme_ty == 1):
            return self.bgv.__repr__()
        elif (self.scheme_ty == 2):
            return self.bfv.__repr__()
        elif (self.scheme_ty == 3):
            return self.tfhe.__repr__()

# Polynomial expression: either cipher or plain
class PolyPexp(Pexp):
    def __init__(self, p):
        self.p = p
        self.tag = 0 # FIX ME tag
        
class Value(IlaExp):
    def __init__(self, v, tag): #, length = None, size = None):
        # self.length = length
        #self.size = size
        self.tag = tag
        self.v = v
        # 0 - integer
        # 1 - cipher
        # 2 - plain
        # 3 - cipher vector
        # 4 - plain vector
        # 10 - iteratable cipher vector
        # 11 - iteratable plain vector
    def __repr__(self):
        if self.tag == 0:
            return 'int %s' % self.v
        if self.tag == 1:
            return 'cipher %s' % self.v
        elif self.tag == 2:
            return 'plain %s' % self.v
        else:
            raise RuntimeError('Unknown tag ' + self.tag)


    def compile(self):
        pass
    
        
    def eval(self, env):
        # Return value
        return self.i

        
class PlainValue(Value):
    def __init__(self, i, backend, scheme_ty):
        self.bgv = None
        self.bfv = None
        self.tfhe = None
        self.scheme_ty =  int(scheme_ty)
        if (self.scheme_ty == 1):
            self.bgv = BGVPlainValue(i, backend)
        elif (self.scheme_ty == 2):
            self.bfv = BFVPlainValue(i, backend)
        elif (self.scheme_ty == 3):
            self.tfhe = TFHEPlainValue(i, backend)
        
    def __repr__(self):
        if (self.scheme_ty == 1):
            return self.bgv.__repr__()
        elif (self.scheme_ty == 2):
            return self.bfv.__repr__()
        elif (self.scheme_ty == 3):
            return self.tfhe.__repr__()
    

    def compile(self):
        pass
    
    def eval(self, env):
        # Return value
        if (self.scheme_ty == 1):
            val = self.bgv.eval(env)
        elif (self.scheme_ty == 2):
            val = self.bfv.eval(env)
        return Value(val.v, val.tag)

    def typeinfer(self, gamma, logq, coeff_mod,plain_mod,d):
        if (self.scheme_ty == 1):
            return self.bgv.typeinfer(gamma, logq, coeff_mod,plain_mod,d)
        elif (self.scheme_ty == 2):
            return self.bfv.typeinfer(gamma, logq, coeff_mod,plain_mod,d)
        elif (self.scheme_ty == 3):
            return self.tfhe.typeinfer(gamma, logq, coeff_mod,plain_mod,d)

    def typecheck(self, gamma):
        if (self.scheme_ty == 1):
            return self.bgv.typecheck(gamma)
        elif (self.scheme_ty == 2):
            return self.bfv.typecheck(gamma)
        elif (self.scheme_ty == 3):
            return self.tfhe.typecheck(gamma)

    def typecheck_relaxed(self, gamma):
        if (self.scheme_ty == 1):
            return self.bgv.typecheck_relaxed(gamma)
        elif (self.scheme_ty == 2):
            return self.bfv.typecheck_relaxed(gamma)
        elif (self.scheme_ty == 3):
            return self.tfhe.typecheck_relaxed(gamma)
    
class VecValue(Value):
    def __init__(self, i, size=None, backend = None, tag = None, length = 0):
        # contains list of types
        self.type_list = []
        self.tag = tag
        self.v = i
        self.backend = backend
        self.eps = None
        self.length = length
        self.size = size
        
    def __repr__(self):
        if self.tag == 3:
            return 'vec;%s;%s%s' % ('cipher' , str(len(self.type_list)) ,json.dumps(self.type_list))
        elif self.tag == 4:
            return 'vec;%s;%s%s' % ('plain' , str(len(self.type_list)) ,json.dumps(self.type_list))
        elif self.tag == 5:
            return 'vec;%s;%d,%d;%s' % ('cipher' , self.size[0],self.size[1] ,json.dumps(self.type_list))
        elif self.tag == 6:
            return 'vec;%s;%d;%d;%s' % ('plain' , self.size[0],self.size[1] ,json.dumps(self.type_list))
    
    def typeinfer(self,gamma, logq, q,t,d):
        if self.tag == 3:
            return("vec", "cipher", len(self.type_list), self.type_list)
        elif self.tag == 4:
            return("vec", "plain", len(self.type_list), self.type_list)
        elif self.tag == 5:
            return("vec", "cipher", self.size, self.type_list)
        elif self.tag == 6:
            return("vec", "plain", self.size, self.type_list)
        else:
            return("vec", ",", self.length, self.type_list)
            
    

    def compile(self):
        pass
    
    def eval(self, env):
        # Return value
        return self

    
class CipherValue(Value):
    def __init__(self, i, backend, scheme_ty):
        self.i = i
        self.bgv = None
        self.bfv = None
        self.tfhe = None
        self.scheme_ty =  int(scheme_ty)
        if (self.scheme_ty == 1):
            self.bgv = BGVCipherValue(i, backend)
        elif (self.scheme_ty == 2):
            self.bfv = BFVCipherValue(i, backend)
        elif (self.scheme_ty == 3):
            self.tfhe = TFHECipherValue(i, backend)
        
    def typecheck_relaxed(self, gamma):
        if (self.scheme_ty == 1):
            return self.bgv.typecheck(gamma)
        elif (self.scheme_ty == 2):
            return self.bfv.typecheck(gamma)
        elif (self.scheme_ty == 3):
            return self.tfhe.typecheck(gamma)
        
    def __repr__(self):
        if (self.scheme_ty == 1):
            return 'cipher %s' % self.bgv.v
        elif (self.scheme_ty == 2):
            return 'cipher %s' % self.bfv.v
        elif (self.scheme_ty == 3):
            return 'cipher %s' % self.tfhe.v
    

    def compile(self):
        s = "client_key.encrypt(" + str(self.i) + ")"
        return s
    
    def eval(self, env):
        # Return value
        if (self.scheme_ty == 1):
            val = self.bgv.eval(env)
        elif (self.scheme_ty == 2):
            val = self.bfv.eval(env)
        return Value(val.v, val.tag)
    
    def typeinfer(self, gamma, logq, coeff_mod,plain_mod,d):
        if (self.scheme_ty == 1):
            return self.bgv.typeinfer(gamma, logq, coeff_mod, plain_mod, d)
        elif (self.scheme_ty == 2):
            return self.bfv.typeinfer(gamma, logq, coeff_mod, plain_mod, d)
        elif (self.scheme_ty == 3):
            return self.tfhe.typeinfer(gamma, logq, coeff_mod, plain_mod, d)
    
    def typecheck(self, gamma):
        if (self.scheme_ty == 1):
            return self.bgv.typecheck(gamma)
        elif (self.scheme_ty == 2):
            return self.bfv.typecheck(gamma)

    def ms_infer(self, gamma_rel, gamma, insert):
        if (self.scheme_ty == 1):
            return self.bgv.ms_infer(gamma_rel, gamma, insert)
        elif (self.scheme_ty == 2):
            return self.bfv.ms_infer(gamma_rel, gamma, insert)
    
    def levelizer(self, gamma):
        return self

    
class IntAexp(Aexp):
    def __init__(self, i):
        self.i = i

    def __repr__(self):
        return 'IntAexp(%d)' % self.i


    def compile(self):
        pass
    
    def eval(self, env):
        # must return a value
        return Value(self.i, 0)
    
    def typecheck(self, gamma):
        return '%s' % ILAInteger()

    def typecheck(self, gamma):
        return '%s' % ILAInteger()

    def typecheck_relaxed(self, gamma):
        return self.typecheck(gamma)
    
class FloatAexp(Aexp):
    def __init__(self, f):
        self.f = f

    def __repr__(self):
        return 'FloatAexp(%d)' % self.f


    def compile(self):
        pass
    
    def eval(self, env):
        # must return a value
        return Value(self.f, 0)
    
    """ def typecheck(self, gamma):
        return '%s' % ILAFloat() """

    def typecheck(self, gamma):
        return '%s' % ILAFloat()

    def typecheck_relaxed(self, gamma):
        return self.typecheck(gamma)

class VarAexp(Aexp):
    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return '%s' % self.name


    def compile(self):
        pass
    
    def eval(self, env):
        if self.name in env:
            return env[self.name]
        else:
            return 0
        
    """ def typecheck(self, gamma):
        return gamma[self.name] """

    def typecheck(self, gamma):
        return gamma[self.name]

    def typecheck_relaxed(self, gamma):
        return self.typecheck(gamma)
    
# class Variable Polynomial Expressions
class VarPexp(Pexp):
    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return '%s' % self.name


    def compile(self):
        return self.name
    
    def eval(self, env):
        if self.name in env:
            return env[self.name]
        else:
            return 0
        
    def typeinfer(self, gamma, logq, coeff_mod,plain_mod,d):
        ty_name = gamma[self.name].split(" ")[0]
        if ty_name == "plain":
            return ("plain", (get_plain_type_attributes(gamma[self.name])))
        elif ty_name == "cipher":
            return ("cipher", (get_cipher_type_attributes(gamma[self.name])))

    def typecheck(self, gamma):
        return gamma[self.name]
    
    def typecheck_relaxed(self, gamma):
        return self.typecheck(gamma)
    

class VarVexp(Vexp):
    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return '%s' % self.name

    def eval(self, env):
        if self.name in env:
            return env[self.name]
        else:
            return 0
        
    def typeinfer(self, gamma, logq, q,t,d):
        return get_vec_type(gamma[self.name])

    def typecheck(self, gamma):
        return gamma[self.name]
    
    def typecheck_relaxed(self, gamma):
        return self.typecheck(gamma)
    

class UnaryopPexp(Pexp):
    def __init__(self, op, exp, backend, scheme_ty):
        self.bgv = None
        self.bfv = None
        self.tfhe = None
        self.scheme_ty =  int(scheme_ty)
        if (self.scheme_ty == 1):
            self.bgv = BGVUnaryopPexp(op, exp, backend)
        elif (self.scheme_ty == 2):
            self.bfv = BFVUnaryopPexp(op, exp, backend)
        elif (self.scheme_ty == 3):
            self.tfhe = TFHEUnaryopPexp(op, exp, backend)
        
    def __repr__(self):
        if (self.scheme_ty == 1):
            return self.bgv.__repr__()
        elif (self.scheme_ty == 2):
            return self.bfv.__repr__()
        elif (self.scheme_ty == 3):
            return self.tfhe.__repr__()


    def compile(self):
        pass
    
    def eval(self, env):
        if (self.scheme_ty == 1):
            v, tag = self.bgv.eval(env)
        elif (self.scheme_ty == 2):
            v, tag = self.bfv.eval(env)
            return Value(v, tag)
        
    def typecheck(self, gamma):
        if (self.scheme_ty == 1):
            self.bgv.typecheck(gamma)
        elif (self.scheme_ty == 2):
            self.bfv.typecheck(gamma)
        
    def typecheck_relaxed(self, gamma):
        if (self.scheme_ty == 1):
            self.bgv.typecheck_relaxed(gamma)
        elif (self.scheme_ty == 2):
            self.bfv.typecheck_relaxed(gamma)
             
    def ms_infer(self, gamma_rel, gamma, insert):
        if (self.scheme_ty == 1):
            self.bgv.ms_infer(gamma_rel, gamma, insert)
        elif (self.scheme_ty == 2):
            self.bfv.ms_infer(gamma_rel, gamma, insert)
        
    def levelizer(self, gamma):
        if (self.scheme_ty == 1):
            return self.bgv.levelizer()
        elif (self.scheme_ty == 2):
            return self.bfv.levelizer()


class BinopPexp(Pexp):
    def __init__(self, op, left, right, backend, scheme_ty):
        self.op = op
        self.left = left
        self.right = right
        self.backend = backend
        self.t1 = None
        self.t2 = None
        self.bgv = None
        self.bfv = None
        self.tfhe = None
        self.scheme_ty =  int(scheme_ty)
        if (self.scheme_ty == 1):
            self.bgv = BGVBinopPexp(op, left, right, backend)
        elif (self.scheme_ty == 2):
            self.bfv = BFVBinopPexp(op, left, right, backend)
        elif (self.scheme_ty == 3):
            self.tfhe = TFHEBinopPexp(op, left, right, backend)
        
    def __repr__(self):
        if (self.scheme_ty == 1):
            return self.bgv.__repr__()
        elif (self.scheme_ty == 2):
            return self.bfv.__repr__()
        elif (self.scheme_ty == 3):
            return self.tfhe.__repr__()
    
    def typeinfer(self, gamma, logq, coeff_mod,plain_mod,d):
        if (self.scheme_ty == 1):
            return self.bgv.typeinfer(gamma, logq, coeff_mod,plain_mod,d)
        elif (self.scheme_ty == 2):
            return self.bfv.typeinfer(gamma, logq, coeff_mod,plain_mod,d)
        elif (self.scheme_ty == 3):
            return self.tfhe.typeinfer(gamma, logq, coeff_mod,plain_mod,d)

    def compile(self):
        sleft = "&" + self.left.compile()
        sright = "&" + self.right.compile()
        if self.op == "@":
            sop = "server_key.unchecked_add("
        elif self.op == "&":
            sop = "server_key.mul("
        else:
            sop = None
        return sop + sleft + ", " + sright + ")"
    
    def eval(self, env):
        if (self.scheme_ty == 1):
            v, tag = self.bgv.eval(env)
            return Value(v, tag)
        if (self.scheme_ty == 2):
            v, tag = self.bfv.eval(env)
            return Value(v, tag)
    
    def t_add_plain_cipher(self, gamma, ty1, ty2, sigma):
        pass

    def typecheck(self, gamma):
        if (self.scheme_ty == 1):
            return self.bgv.typecheck(self.gamma)
        elif (self.scheme_ty == 2):
            return self.bfv.typecheck(self.gamma)
           

    def typecheck_relaxed(self, gamma):
        if (self.scheme_ty == 1):
            return self.bgv.typecheck_relaxed(gamma)
        elif (self.scheme_ty == 2):
            return self.bfv.typecheck_relaxed(gamma)
    
    def ms_infer(self, gamma_rel, gamma, insert):
        if (self.scheme_ty == 1):
            return self.bgv.ms_infer(gamma_rel, gamma, insert)
        elif (self.scheme_ty == 2):
            return self.bfv.ms_infer(gamma_rel, gamma, insert)
    
    def levelizer(self, gamma):
        if (self.scheme_ty == 1):
            return self.bgv.levelizer(gamma)
        elif (self.scheme_ty == 2):
            return self.bfv.levelizer(gamma)

class BinopVexp(Vexp):
    def __init__(self, op, left, right, backend, scheme_ty):
        self.op = op
        self.left = left
        self.right = right
        self.backend = backend
        self.t1 = None
        self.t2 = None
        self.scheme_ty = scheme_ty

    def __repr__(self):
        return '(%s %s %s)' % (self.left, self.op, self.right)
    # type_name, sort_exp, lenght, alpha_list
    def typeinfer(self, gamma, logq, q, plain_mod,degree):
        if "*" == self.op:
                ltype, lsort, llenght, lalpha = self.left.typeinfer(gamma, logq, q, plain_mod,degree)
                _, rsort, rlenght, ralpha = self.left.typeinfer(gamma, logq, q, plain_mod,degree)
                #if llenght != rlenght:
                #    raise Exception("Operation is not defined on vectors of different legths &")
                alpha_in_result = []
                # noise = 0
                for index, lval in enumerate(lalpha):
                    rval = ralpha[index]
                    linf = lval[0]
                    lsup = lval[1]
                    leps = lval[2]
                    rinf = rval[0]
                    rsup = rval[1]
                    reps = rval[2]
                    llevel = rlevel = -1
                    if lsort == 'plain':
                        rlevel = rval[3]
                    elif rsort == 'plain':
                        llevel = lval[3]
                    #if (llevel != -1) and (rlevel != -1) and (llevel != rlevel) :
                    #    raise Exception("Level mis-match at &")
                    inf = min([linf*rinf, linf*rsup, rinf*lsup, lsup*rsup])
                    sup = max([linf*rinf, linf*rsup, rinf*lsup, lsup*rsup])
                    new_eps = leps*reps + plain_mod * degree * (2 ** 90) * 3.2 * math.sqrt ( logq/30 + 3)
                    if new_eps > q/2:
                        raise Exception("Noise overflow at %s" % self)
                    alpha_in_result.append((inf,sup, new_eps, max(llevel, rlevel)))
                #self.tag = 3  
                return(ltype,"cipher", len(alpha_in_result),alpha_in_result)
        elif "+" == self.op:
                ltype, lsort, llenght, lalpha = self.left.typeinfer(gamma, logq, q, plain_mod,degree)
                _, rsort, rlenght, ralpha = self.left.typeinfer(gamma, logq, q, plain_mod,degree)
                if llenght != rlenght:
                    raise Exception("Operation is not defined on vectors of different legths &")
                alpha_in_result = []
                # noise = 0
                for index, lval in enumerate(lalpha):
                    rval = ralpha[index]
                    linf = lval[0]
                    lsup = lval[1]
                    leps = lval[2]
                    rinf = rval[0]
                    rsup = rval[1]
                    reps = rval[2]
                    llevel = rlevel = -1
                    if lsort == 'plain':
                        rlevel = rval[3]
                    elif rsort == 'plain':
                        llevel = lval[3]
                    if (llevel != -1) and (rlevel != -1) and (llevel != rlevel) :
                        raise Exception("Level mis-match at &")
                    if reps + leps > q/2:
                        raise Exception("Noise overflow at %s" % self)
                    alpha_in_result.append((linf+rinf,lsup+rsup, reps + leps, max(llevel, rlevel)))
                #self.tag = 3  
                return(ltype,"cipher", len(alpha_in_result),alpha_in_result)
        elif "$" == self.op:
                ltype, lsort, lsize, lalpha = self.left.typeinfer(gamma, logq, q, plain_mod,degree)
                _, rsort, rsize, ralpha = self.left.typeinfer(gamma, logq, q, plain_mod,degree)
                (lrows, lcolmns) = lsize
                (rrows, rcolmns) = rsize
                if lcolmns != rrows:
                    raise Exception("Incompatible matrices")
                t = [ [lalpha[0][0] for x in range(len(lalpha))] for y in range(len(ralpha[0]))]
                for i in range (len(lalpha)):
                    for j in range(len(ralpha[0])):
                        for k in range(len(ralpha)):
                            #temp_list = [0, 0 , 0, 0]
                            #for index in range(len(lalpha[i][k])):
                            #    temp_list[index] = lalpha[i][k][index] * ralpha[k][j][index]
                            t[i][j] = lalpha[i][k]
                return(ltype,"cipher", (lrows,rcolmns), t)
        elif 'idx' == self.op:
            vtype, sort, length, li = self.left.typeinfer(gamma, logq, q, plain_mod, degree)
            # FIXME: Super ugly approximation.
            # For inference to work properly, we need dependent types
            # the index should be known at compile time.
            # The issue is somewhat orthogonal and needs to be handled later
            bounds = li[0]
            return sort, (bounds[0], bounds[1], bounds[2], bounds[3])

    def compile(self):
        pass
    

    def eval(self, env):
        left_value = self.left.eval(env)
        right_value = self.right.eval(env)
        vec_tag = 3
        size = (0,0)
        if self.op == '*':
            if left_value.tag == 3 and right_value.tag == 3:
                v = self.backend.vec_mult(left_value.v, right_value.v)
            elif left_value.tag == 4 and right_value.tag == 3:
                v = self.backend.vec_plain_mult(right_value.v, left_value.v)
            elif left_value.tag == 3 and right_value.tag == 4:
                v = self.backend.vec_plain_mult(left_value.v, right_value.v)
            else:
                v = self.backend.plain_mult(left_value.v, right_value.v)
                vec_tag = 2
                
        elif self.op == '+':
            if left_value.tag == 3 and right_value.tag == 3:
                v = self.backend.cipher_add(left_value.v, right_value.v)
            elif left_value.tag == 4 and right_value.tag == 3:
                v = self.backend.cipher_plain_add(right_value.v, left_value.v)
            elif left_value.tag == 3 and right_value.tag == 4:
                v = self.backend.cipher_plain_add(left_value.v, right_value.v)
            else:
                v = self.backend.plain_add(left_value.v, right_value.v)
                vec_tag = 2
        elif self.op == '$':
            if left_value.tag == 5 and right_value.tag == 5:
                v = self.backend.cipher_mat_mult(left_value.v, right_value.v)
                (lrows, _) = left_value.size
                (_, rcol) = right_value.size
                size = (lrows, rcol)
                vec_tag = 5
            elif left_value.tag == 6 and right_value.tag == 5:
                v = self.backend.cipher_plain_mat_mult(right_value.v, left_value.v)
            elif left_value.tag == 5 and right_value.tag == 6:
                v = self.backend.cipher_plain_mat_mult(left_value.v, right_value.v)
            else:
                v = self.backend.plain_add(left_value.v, right_value.v)
                vec_tag = 2
        elif self.op == "idx":
            # At this point left_value should be a VecValue object with
            # actual vectors stored in the attribute 'v'.
            # Note right_value should be less than the size.
            idx = int(right_value.v)
            if idx < left_value.length:
                # We always need to return a value
                if left_value.tag == 3:
                    # This is a cipher vector
                    return Value((left_value.v)[idx], 1)
                elif left_value.tag == 4:
                    # This is a plain vector
                    return Value((left_value.v)[idx], 2)
            else:
                #raise out-of-bounds  exception here
                return None
        else:
            raise RuntimeError('unknown operator: ' + self.op)
        return VecValue(v, tag = vec_tag, size = size, length=left_value.length )#, self.left.length)


class BinopAexp(Aexp):
    def __init__(self, op, left, right):
        self.op = op
        self.left = left
        self.right = right

    def __repr__(self):
        return 'BinopAexp(%s, %s, %s)' % (self.op, self.left, self.right)

    def eval(self, env):
        left_value = self.left.eval(env)
        right_value = self.right.eval(env)
        if self.op == '+':
            value = left_value.v + right_value.v
        elif self.op == '-':
            value = left_value.v - right_value.v
        elif self.op == '*':
            value = left_value.v * right_value.v
        elif self.op == '/':
            value = left_value.v / right_value.v
        else:
            raise RuntimeError('unknown operator: ' + self.op)
        return Value(value, 0)
    
    def typecheck(self, gamma):
        t1 = self.left.typecheck(gamma)
        t2 = self.right.typecheck(gamma)
        
        #ToDo: Raise an exception if t1 != t2
        return '%s' % ILAInteger()

    def typecheck_relaxed(self, gamma):
        return self.typecheck(gamma)
    
    def ms_infer(self, gamma_rel, gamma, insert):
        newexpty = self.typecheck(gamma)
        return self, False, newexpty
 
    def levelizer(self, gamma):
        return self
