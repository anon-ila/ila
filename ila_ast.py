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
import math
import sys
import numpy as np
import gc
import json

func_correct = True
perf = True

class TypecheckError(Exception):
    def __init__(self, message, error_code):            
        # Call the base class constructor with the parameters it needs
        super().__init__(message)
            
        # Now for your custom code...
        self.error_code = error_code
        
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
    
def get_cipher_type_attributes(t):
    c, inf, sup, eps, om = t.split(" ")
    inf = inf[1:-1]
    sup = sup[:-1]
    eps = eps[:-1]
    om = om[:-1]
    if inf != 'None':
        inf = float(inf)
    else:
        inf = None
    if sup != 'None':
        sup = float(sup)
    else:
        sup = None
    return inf, sup, float(eps), int(om)

def get_vec_type(t):
   # vec;cipher;lenght;type_list
    lst = t.split(";")
    if len(lst) == 5:
        return lst[0], lst[1], (int(lst[2]), int(lst[3])), json.loads(lst[4])
    return lst[0], lst[1], int(lst[2]), json.loads(lst[3])

def get_plain_type_attributes(t):
    _, inf, sup, noise = t.split(" ")
    inf = inf[1:-1]
    sup = sup[:-1]
    noise = noise[:-1]
    if inf != 'None':
        inf = float(inf)
    else:
        inf = None
    if sup != 'None':
        sup = float(sup)
    else:
        sup = None
    return inf, sup, float(noise)

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
    def __init__(self, name, exp):
        # self.name := self.exp
        self.name = name
        self.exp = exp
        
    def __repr__(self):
        return '%s := %s' % (self.name, self.exp)

    def compile(self):
        s_name = self.name
        s_exp = self.exp.compile()
        s = "let mut " + s_name + " = " + s_exp + ";\n"
        return s
    
    def eval(self, env):
        value = self.exp.eval(env)
        env[self.name] = value
        
    def is_sub_type (self, type_1, type_2):
        # (inf_name, sup_name, eps_name, om_name) is a sub type of (inf_exp, sup_exp, eps_exp, om_exp)
        # if inf_exp == None then inf_name = None
        # if sup_exp == None then sup_name = None
        # None <= any_rational and any_rational >= None
        # if inf_exp <= inf_name <= sup_name <= sup_exp and
        # eps_name < eps_expr and both levels are the same.
        # if  inf_exp <= inf_name <= sup_name <= sup_exp and eps_name < eps_expr  but om_name > om_exp
        # this can be fixed with mod switching 
        (inf_name, sup_name, eps_name) = type_1
        (inf_exp, sup_exp, eps_exp) = type_2
        if inf_name == 'NaN' and sup_name == 'NaN':
            return (eps_name < eps_exp)
        if sup_exp == 'NaN' and inf_exp == 'NaN':
            return (eps_name < eps_exp)
        elif inf_name == 'NaN':
            if sup_exp != "fresh":
                return (sup_exp > sup_name) and (eps_name < eps_exp)
            else:
                return (eps_name < eps_exp)
        elif sup_name == 'NaN':
            if sup_exp != "fresh":
                return (inf_exp < inf_name) and (eps_name < eps_exp)
            else:
                return (eps_name < eps_exp)
        elif sup_exp == 'NaN':
            return (inf_exp < inf_name) and (eps_name < eps_exp)
        elif inf_exp == 'NaN':
            return (sup_exp > sup_name) and (eps_name < eps_exp)
        if inf_exp != "fresh" and sup_exp != "fresh":
                if inf_name < inf_exp or sup_name > sup_exp:
                    return 0
        if eps_name > eps_exp:
            return 0
        return 1
                
                
    def typeinfer(self, gamma, logq, q,t,d):
        error = ""
        if 'matrix' in gamma[self.name]:
            type_exp, sort_exp, size_exp, alpha_list = self.exp.typeinfer(gamma, logq, q,t,d)
            type_name, sort_name, size_name, type_list = get_vec_type(gamma[self.name])
            rows = size_name[0]
            colmns = size_name[1]
            if sort_exp != sort_name and alpha_list != []:
                raise TypecheckError("cannot assign %s vec to a %s vec in %s\n" % (sort_exp, sort_name, self), 2)
            if alpha_list == []: # means we are at  VecValue
                # n = |(e_i)|
                if sort_name == 'cipher':
                    self.exp.tag = 5
                    sort_exp = sort_name
                    if rows != len(self.exp.v):
                        raise TypecheckError("type has %d rows, exp has  %d rows in %s\n" % (rows, len(self.exp.v), self), 2)
                    new_v = []
                    new_eps = []
                    l = self.exp.bgv.get_modulus_chain_highest_level()
                    for index, ele in enumerate(self.exp.v):
                        if len(ele) != colmns:
                            raise TypecheckError("type has %d columns, exp has  %d columns in %s\n" % (colmns, len(ele), self), 2)
                        new_col = []
                        new_noise = []
                        for colmn_index, colmn_ele in enumerate(ele):
                            value, noise = self.exp.bgv.cipher_init(colmn_ele)
                            new_col.append(value)
                            new_noise.append(noise)
                            type_list[index][colmn_index] = (float('NaN'),float('NaN'),noise, l) 
                        new_v.append(new_col)
                        new_eps.append(new_noise)
                    self.exp.v = new_v
                    self.exp.eps = new_eps
                    self.exp.type_list = type_list
                    gamma[self.name] = type_name+";"+sort_name+";"+str(rows)+";"+str(colmns)+';'+json.dumps(type_list)
                    return("", gamma)
                else:
                    self.exp.tag = 6
                    sort_exp = sort_name
                    if rows != len(self.exp.v):
                        raise TypecheckError("type has %d rows, exp has  %d rows in %s\n" % (rows, len(self.exp.i), self), 2)
                    new_v = []
                    new_eps = []
                    for index, ele in enumerate(self.exp.v):
                        if len(ele) != colmns:
                            raise TypecheckError("type has %d columns, exp has  %d columns in %s\n" % (colmns, len(ele), self), 2)
                        new_col = []
                        new_noise = []
                        for colmn_index, colmn_ele in enumerate(ele):
                            new_v = PlainValue(colmn_ele, self.exp.bgv)
                            value = new_v.v
                            noise = new_v.eps
                            new_col.append(value)
                            new_noise.append(noise)
                            type_list[index][colmn_index] = [(float('NaN'),float('NaN'),noise)]
                        new_v.append(new_col)
                        new_eps.append(new_noise)
                    self.exp.v = new_v
                    self.exp.eps = new_eps
                    self.exp.type_list = type_list
                    gamma[self.name] = type_name+";"+sort_name+";"+str(rows)+";"+str(colmns)+';'+json.dumps(type_list)
            return("", gamma)

        elif 'vec' in gamma[self.name]:
            type_exp, sort_exp, length_exp, alpha_list = self.exp.typeinfer(gamma, logq, q,t,d)
            type_name, sort_name, length_name, type_list = get_vec_type(gamma[self.name])
            if sort_exp != sort_name and alpha_list != []:
                raise TypecheckError("cannot assign %s vec to a %s vec in %s\n" % (sort_exp, sort_name, self), 2)
            if len(type_list) > 0 and len(type_list) != length_name: 
                type_list.extend([type_list[-1]] * (length_name - len(type_list)))
            if alpha_list == []: # means we are at  VecValue
                # n = |(e_i)|
                if sort_name == 'cipher':
                    self.exp.tag = 3
                    sort_exp = sort_name
                    self.exp.v, self.exp.eps = self.exp.bgv.vec_init(self.exp.v, 3) #as self.exp.tag == 3
                    if len(type_list) == 0: #means type declaration is like x : vec cipher n 
                        l = self.exp.bgv.get_modulus_chain_highest_level()
                        type_list.extend([(float('NaN'),float('NaN'),self.exp.eps,l)] * length_name)
                        gamma[self.name] = type_name+";"+sort_name+";"+str(length_name)+';'+json.dumps(type_list)
                        self.exp.type_list = type_list
                        self.exp.length = length_name
                        return("", gamma)
                else:
                    self.exp.tag = 4
                    sort_exp = sort_name
                    self.exp.v, self.eps = self.exp.bgv.vec_init(self.exp.v, 4 ) # as self.exp.tag == 4
                    type_list.extend([(float('NaN'),float('NaN'),self.exp.eps)] * length_name)
                    gamma[self.name] = type_name+";"+sort_name+";"+str(length_name)+';'+json.dumps(type_list)
                    self.exp.type_list = type_list
                    self.exp.length = length_name
                    return("", gamma)
            else:
                if sort_name != sort_exp:
                    raise TypecheckError("Vec type has both cipher and plain types %s\n" % self, 2)
                if length_name != length_exp:
                    raise TypecheckError('vec %d type has %d arguments at %s' % (length_name, len(self.exp.v) ,self.exp), 11)
                gamma[self.name] = type_exp+";"+sort_exp+";"+str(length_name)+';'+json.dumps(alpha_list)
                # FIX ME: Fill me
                return("", gamma)
        
        elif 'cipher' in gamma[self.name]:
            type_name, (inf_exp, sup_exp, eps_exp, om_exp) = self.exp.typeinfer(gamma)
            if type_name != "cipher":
                raise TypecheckError('Exp type is' + type_name + '; expected cipher: %s\n' %  self, 11)
            (inf_name, sup_name, eps_name, om_name) = get_cipher_type_attributes(gamma[self.name])
            if (inf_exp == "fresh") and (sup_exp == "fresh"):
                self.exp.inf = inf_exp = inf_name
                self.exp.sup = sup_exp = sup_name
            if self.is_sub_type((inf_name, sup_name, eps_name), (inf_exp, sup_exp, eps_exp)):
                if om_name != om_exp:
                    if om_name > om_exp:
                        raise TypecheckError('Level mismatch in the assignment: %s\n' % self, 13)
                    else:
                        raise TypecheckError('Level mismatch in the assignment: %s\n' % self, 11)
            else:
                raise TypecheckError(self.name + ' is not a subtype in the assignment: %s\n' % self, 11)
            gamma[self.name] = "cipher <" + str(inf_exp)+ ", " + str(sup_exp)+ ", " + str(eps_exp)+ ", " + str(om_exp)+ ">"
            if eps_exp > q:
                raise TypecheckError(' Noise over flow: %s\n' % self, 11)
            if (inf_exp != 'NaN' and inf_exp <= -t/2) or (sup_exp != 'NaN' and sup_exp > t/2):
                error = "Plain text over flow at" + self
            return (error, gamma)
        elif 'plain' in gamma[self.name]:
            type_name, exp_type = self.exp.typeinfer(gamma)
            if type_name != "plain":
                raise TypecheckError('Exp type is' + type_name + '; expected plain: %s\n' %  self, 11)
            (inf_name, sup_name, eps_name) = get_plain_type_attributes(gamma[self.name])
            (inf_exp, sup_exp, eps_exp) = exp_type
            if (inf_exp == "fresh") and (sup_exp == "fresh"):
                self.exp.inf = inf_exp = inf_name
                self.exp.sup = sup_exp = sup_name
            if not self.is_sub_type((inf_name, sup_name, eps_name), (inf_exp, sup_exp, eps_exp)):
                TypecheckError(self.name + ' is not a subtype in the assignment: %s\n' % self, 11)
            gamma[self.name] = "plain <" + str(inf_exp)+ ", " + str(sup_exp)+ ", " + str(eps_exp)+ ">"
            if eps_exp > q:
                raise TypecheckError(' Noise over flow: %s\n' % self, 11)
            if (inf_exp != 'NaN' and inf_exp <= -t/2) or (sup_exp != 'NaN' and sup_exp > t/2):
                error = "Plain text over flow at" + self
            return (error, gamma)

    def typecheck(self, gamma):
        try:
            self.expty = self.exp.typecheck(gamma)
        except Exception as e1:
            raise e1
        try:
            # t <= gamma[self.name]
            if (is_subtype(self.expty, gamma[self.name])):
                return True
        except Exception as e:
            msg = str(e)
            code = e.error_code
            raise TypecheckError('Subtype check failed in the assignment: %s\n' % self, code)
            
        
    def typecheck_relaxed(self, gamma):
        t = self.exp.typecheck_relaxed(gamma)
        # t subtype gamma[self.name]
        if (is_subtype(t, gamma[self.name])):
            return True
        else:
            return False
        
    def ms_infer(self, gamma_rel, gamma, om):
        insert = False
        this_om = self.get_modswitch_depth(gamma)
        if this_om >= om:
            insert = True
        newexp, changed, newexpty = self.exp.ms_infer(gamma_rel, gamma, insert)
        gamma[self.name] = newexpty
        return AssignStatement(self.name, newexp), changed, gamma
        
    def levelizer(self, gamma):
        newexp = self.exp.levelizer(gamma)
        return AssignStatement(self.name, newexp)

    def get_modswitch_depth(self, gamma):
        vartype = gamma[self.name]
        if is_cipher_type(vartype):
            _, _, _, om = get_cipher_type_attributes(vartype)
            return om
        else:
            return 'NaN'
    
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
            raise TypecheckError('Conditional expression %s has non-boolean type.\n' % self.condition, 2)


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
            raise TypecheckError('Conditional expression %s has non-boolean type.\n' % self.condition, 2)

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

    def compile(self):
        pass
    
    def eval(self, env):
        condition_value = self.condition.eval(env)
        while condition_value:
            self.body.eval(env)
            condition_value = self.condition.eval(env)

    def typecheck(self, gamma):
        return False
 

class IlaType(Type):
    def __init__(self, t):
        self.ty = t
    def __repr__(self):
        return '%s' % self.ty

    
class VecType(IlaType):
    def __init__(self, tyname, sort, tylist, tag, size, length = 0):
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
    def __init__(self, tyname, inf, sup, eps, om):
        self.ty = tyname
        self.inf = inf
        self.sup = sup
        self.eps = eps
        self.om = om
    def __repr__(self):
        return 'cipher <%s, %s, %s, %s>' % (self.inf, self.sup, self.eps, self.om)


class PlainType(IlaType):
    def __init__(self, tyname, inf, sup, eps):
        self.ty = tyname
        self.inf = inf
        self.sup = sup
        self.eps = eps
    def __repr__(self):
        return 'plain <%s, %s, %s>' % (self.inf, self.sup, self.eps)


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
        return self

        
class PlainValue(Value):
    def __init__(self, i, backend):
        # set tag to cipher
        self.tag = 2
        # call backend module
        self.v, self.eps = backend.plain_init(i)
        self.inf = None
        self.sup = None
        
    def __repr__(self):
        return 'plain %s' % self.v
    

    def compile(self):
        pass
    
    def eval(self, env):
        # Return value
        return self

    def typeinfer(self, gamma):
        return ('plain', ("fresh", "fresh", self.eps))

    def typecheck(self, gamma):
        return '%s' % PlainType('plain', self.inf, self.sup)

    def typecheck_relaxed(self, gamma):
        return self.typecheck(gamma)
    
class VecValue(Value):
    def __init__(self, i, size, backend = None, tag = None, length = None):
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
    def __init__(self, i, backend):
        # set tag to cipher
        self.tag = 1
        self.i = str(int(float(i)))
        self.v = None
        # call bgv module
        try:
            f = float(i)
            self.v, noise = backend.cipher_init(f)
        except ValueError:
            self.v, noise = backend.cipher_poly_init(i)

        norm_ty = backend.get_norm_type()
        self.om = backend.get_modulus_chain_highest_level()
        self.logq, self.t, self.d = backend.get_params(self.om)

        # compute ila homomorphic noise from SEAL's noise budget
        if norm_ty == 1:
            # supremum norm initial noise
            # 2^(logq - noise - 1)
            self.eps = pow(2, (self.logq - noise - 1))
        elif norm_ty == 2:
            # Canonical Norm initial noise
            # 6 * {\sqrt(d*t^2* (1/12 + (3.2)^2 (4*d /3 + 1)}
            tmp = self.d  * ( (1/12) + ((3.2 * 3.2) * ((4 * self.d/3) + 1)) )
            tmp_sqrt = math.sqrt(tmp)
            self.eps = 6 * self.t * tmp_sqrt
        elif norm_ty == 3:
            # Canonical Norm initial noise - version 2
            # 6 * {\sqrt(d*t^2* (1/12 + (19.2)^2 (4*d /3 + 1)}
            self.eps = 6 * self.t * math.sqrt( self.d * ( (1/12) + (19.2 * 19.2) * ((4 * self.d)/3) +1))

            
    def typecheck_relaxed(self, gamma):
        return self.typecheck(gamma)
        
    def __repr__(self):
        return 'cipher %s' % self.v
    

    def compile(self):
        s = "client_key.encrypt(" + str(self.i) + ")"
        return s
    
    def eval(self, env):
        # Return value
        return self
    
    def typeinfer(self, gamma):
        return ('cipher', ("fresh", "fresh", self.eps, self.om))
    
    def typecheck(self, gamma):
        return '%s' % CipherType('cipher', self.inf, self.sup, self.eps, self.om)

    def ms_infer(self, gamma_rel, gamma, insert):
        newexpty = self.typecheck(gamma)
        return self, False, newexpty

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
    
    """ def typecheck(self, gamma):
        return '%s' % ILAInteger() """

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
        
    def typeinfer(self, gamma):
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
    def __init__(self, op, exp, backend):
        self.op = op
        self.exp = exp
        self.backend = backend
        
    def __repr__(self):
        return '%s(%s)' % (self.op, self.exp)


    def compile(self):
        pass
    
    def eval(self, env):
        val = self.exp.eval(env)
        return Value(self.backend.modswitch(val.v), 1)

    """ def typecheck(self, gamma):
        raise RuntimeError('Type check not implemented\n') """

    def typecheck(self, gamma):
        L = self.backend.get_modulus_chain_highest_level()
        qlist = self.backend.get_modulus_chain()
        ty = self.exp.typecheck(gamma)
        if is_cipher_type(ty):
            inf, sup, eps, omega = get_cipher_type_attributes(ty)
            #use omega-1 due to modswitch
            logq, t, d, l = self.backend.get_params(omega-1)
            # 6*t*\sqrt(d/12(1+2*d/3))
            tmp1 = math.sqrt((d/12)*(1+((2*d)/3)))
            br = 6 * t * tmp1
            # 22 t \sqrt (3d)
            tmp3 = math.sqrt((d/12)*(1+((2*64*d)/3)))
            br1 = 6 * t * tmp3
            
            
            eps1 = ((qlist[omega-1]/qlist[omega]) * eps) + br1
            cl = self.backend.get_coeff_modulus_list()
            
            sys.stdout.write('================================\n')
            sys.stdout.write('coeff mod[omega-1]  %d\n' % cl[omega-1].value())
            sys.stdout.write('coeff mod[omega]  %d\n' % cl[omega].value())
            sys.stdout.write('================================\n')
            for i in range(1, 12):
                tmp = 2* math.pow(eps1, i) - qlist[omega-1]
                if tmp > 0:
                    tmp2 = i
                    sys.stdout.write('================================\n')
                    sys.stdout.write('MS depth :  %d\n' % tmp2)
                    sys.stdout.write('================================\n')
                    break
                
            if 0 <= (omega -1) <= L:
                if eps1 <= l:
                    return '%s' % CipherType('cipher',sup, inf, eps1, (omega-1))
                else:
                    raise TypecheckError('modswitch typing error: noise out of bounds\n', 3)
            else:
                raise TypecheckError('modswitch typing error: incorrect level \n', 4)
        else:
            raise TypecheckError('modswitch typing error: modulus switching applied to non-cipher typed expression %s\n' % self.exp, 5)

    def typecheck_relaxed(self, gamma):
        L = self.backend.get_modulus_chain_highest_level()
        qlist = self.backend.get_modulus_chain()
        q0 = qlist[0]
        ql = qlist[-1]
        ty = self.exp.typecheck_relaxed(gamma)
        if is_cipher_type(ty):
            inf, sup, eps, omega = get_cipher_type_attributes(ty)
            logq, t, d, l = self.backend.get_params(omega-1)
            br = 77 * math.sqrt(d)
            eps1 = ((qlist[omega-1]/qlist[omega]) * eps) + br
            if 0 <= (omega -1) <= L:
                f = (q0//ql)* eps
                if f <= l:
                    return '%s' % CipherType('cipher',sup, inf, eps1, (omega-1))
                else:
                    raise RuntimeError('Relaxed modswitch typing error: noise out of bounds\n')
            else:
                raise RuntimeError('Relaxed modswitch typing error: incorrect level \n')
        else:
            raise RuntimeError('Relaxed modswitch typing error\n')

             
    def ms_infer(self, gamma_rel, gamma, insert):
        newexpty = self.typecheck(gamma)
        if insert:
            newexp = UnaryopPexp('ms', self, self.backend)
            newexpty = newexp.typecheck(gamma)
            return newexp, True, newexpty
        else:
            return self, False, newexpty
 
    def levelizer(self, gamma):
        return self


class BinopPexp(Pexp):
    def __init__(self, op, left, right, backend):
        self.op = op
        self.left = left
        self.right = right
        self.backend = backend
        self.t1 = None
        self.t2 = None

    def __repr__(self):
        return '(%s %s %s)' % (self.left, self.op, self.right)
    
    def typeinfer(self, gamma):
        if "&" == self.op:
            ltyname, (linf,lsup,lnoise,llevel) = (self.left).typeinfer(gamma)
            rtyname, (rinf,rsup,rnoise,rlevel) = (self.right).typeinfer(gamma)
            if ltyname == rtyname == "plain":
                raise Exception("Plain multiplication is not supported currently")
            if (llevel != -1) and (rlevel != -1) and (llevel != rlevel) :
                raise Exception("Level mis-match at &")
            if linf == None or rinf == None:
                inf = None
            if rsup == None or lsup == None:
                sup = None
            else:
                inf = min([linf*rinf, linf*rsup, rinf*lsup, lsup*rsup])
                sup = max([linf*rinf, linf*rsup, rinf*lsup, lsup*rsup])
            level = max(llevel, rlevel)
            # relin noise = (lnoise * rnoise) + (t * d * w * \sigma * \sqrt(3) * \sqrt(ell+1))
            # ell = log q/loq w ; in seal log w is undefined.
            # assuming log w = 90   
            logq, plain_mod , degree = self.backend.get_params(level)
            return("cipher", (inf,sup, (lnoise*rnoise) + (plain_mod * degree * (2 ** 90) * 3.2 * math.sqrt ( logq/30 + 3)), level))
            #return("cipher", (inf,sup, (lnoise*rnoise), level))
        if "@" == self.op:
            ltyname, (linf,lsup,lnoise,llevel) = (self.left).typeinfer(gamma)
            rtyname, (rinf,rsup,rnoise,rlevel) = (self.right).typeinfer(gamma)
            if ltyname == rtyname == "plain":
                raise Exception("Plain addition is not supported currently")
            if llevel != -1 and rlevel != -1 and llevel != rlevel :
                raise Exception("Level mis-match")
            if linf == None or rinf == None:
                inf = None
            if rsup == None or lsup == None:
                sup = None
            else:
                inf = linf+rinf
                sup = lsup+rsup
            return "plain",(inf, sup, lnoise+rnoise,  max(llevel, rlevel))
            


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
        left_value = self.left.eval(env)
        right_value = self.right.eval(env)
        tag = 1
        if self.op == '&':
            if left_value.tag == 1 and right_value.tag == 1:
                v = self.backend.cipher_mult(left_value.v, right_value.v)
            elif left_value.tag == 2 and right_value.tag == 1:
                v = self.backend.cipher_plain_mult(right_value.v, left_value.v)
            elif left_value.tag == 1 and right_value.tag == 2:
                v = self.backend.cipher_plain_mult(left_value.v, right_value.v)
            else:
                v = self.backend.plain_mult(left_value.v, right_value.v)
                tag = 2
                
        elif self.op == '@':
            if left_value.tag == 1 and right_value.tag == 1:
                v = self.backend.cipher_add(left_value.v, right_value.v)
            elif left_value.tag == 2 and right_value.tag == 1:
                v = self.backend.cipher_plain_add(right_value.v, left_value.v)
            elif left_value.tag == 1 and right_value.tag == 2:
                v = self.backend.cipher_plain_add(left_value.v, right_value.v)
            else:
                v = self.backend.plain_add(left_value.v, right_value.v)
                tag = 2
        else:
            raise RuntimeError('unknown operator: ' + self.op)
        return Value(v, tag)

    def t_add_plain_cipher(self, gamma, ty1, ty2, sigma):
        pass

    def typecheck(self, gamma):

        self.t1 = self.left.typecheck(gamma)
        self.t2 = self.right.typecheck(gamma)
        #logq, t, d, l = self.backend.get_params()
        norm_ty = self.backend.get_norm_type()
        if self.op == '&':
            if is_cipher_type(self.t1) and is_cipher_type(self.t2):
                #Compute new inf and sup
                inf1, sup1, eps1, om1 = get_cipher_type_attributes(self.t1)
                inf2, sup2, eps2, om2 = get_cipher_type_attributes(self.t2)
                logq, t, d, l = self.backend.get_params(om1)
                inf = min([inf1*inf2, inf1*sup2, inf2*sup1, sup1*sup2])
                sup = max([inf1*inf2, inf1*sup2, inf2*sup1, sup1*sup2])
                
                if norm_ty == 1:
                   # supremum norm
                   # raw noise multiplication---very inefficient.
                   eps = eps1 * eps2
                   # # SEAL noise estimation: t * sqrt(3) * d * (v1 + v2 +1) + k
                   # two_pow = pow(2, 60)
                   # m = 19.2 * 8192 * two_pow * (1 + math.log(2*l, two_pow))
                   # k = t/l * m
                   # eps = t  * 6 * d * (eps1 + eps2 + math.sqrt(12 * d)) + k
                elif norm_ty ==2:
                    #canonical norm multiplicative noise
                    eps = eps1 * eps2 + (77 * math.sqrt(d))
                elif norm_ty == 3:
                    #canonical norm multiplicative noise
                    eps = eps1 * eps2 + (77 * math.sqrt(d))
                else:
                    raise RuntimeError('Unknown norm\n')
                
                if om1 == om2:
                   #Check if new and sup are within the range of t
                   if func_correct:
                       if (-t/2 <= inf <= sup < t/2):
                           # check if eps is within noise bound
                           if ( eps <= l):
                               return '%s' % CipherType('cipher',sup, inf, eps, om1)
                           else:
                               raise TypecheckError('Typecheck error: noise out of bounds for the selfession: %s' %  self, 3)
                       else:
                           raise TypecheckError('Typecheck error: value out of bounds for the expression: %s' % self, 6)
                   else:
                           # check if eps is within noise bound
                           if ( eps <= l):
                               return '%s' % CipherType('cipher',sup, inf, eps, om1)
                           else:
                               raise TypecheckError('Typecheck error: noise out of bounds for the expression: %s' %  self, 3)
                else:
                    raise TypecheckError('Operation between mismatched levels %s\n' % self, 7)
                
            elif  is_plain_type(self.t1) and is_cipher_type(self.t2):
                #Compute new inf and sup
                val, delta = get_plain_type_attributes(self.t1)
                inf1, sup1, eps1, om1 = get_cipher_type_attributes(self.t2)
                _ , t, d, l = self.backend.get_params(om1)
                inf = inf1 * val
                sup = sup1 * val
                eps = eps1 * delta
            
                #Check if new and sup are within the range of t
                if (-t/2 <= inf <= sup < t/2):
                    # check if eps is within noise bound
                    if ( eps <= l):
                        return '%s' % CipherType('cipher',sup, inf, eps, om1)
                    else:
                               raise TypecheckError('Typecheck error: noise out of bounds for the expression: %s' %  self, 3)
                else:
                           raise TypecheckError('Typecheck error: value out of bounds for the expression: %s' % self, 6)

            elif  is_cipher_type(self.t1) and is_plain_type(self.t2):
                #Compute new inf and sup
                val, delta = self.get_plain_type_attributes(self.t2)
                inf1, sup1, eps1, om1 = self.get_cipher_type_attributes(self.t1)
                logq, t, d, l = self.backend.get_params(om1)
                inf = inf1 * val
                sup = sup1 * val
                eps = eps1 * delta
            
                #Check if new and sup are within the range of t
                if (-t/2 <= inf <= sup < t/2):
                    # check if eps is within noise bound
                    if ( eps <= l):
                        return '%s' % CipherType('cipher',sup, inf, eps, om1)
                    else:
                               raise TypecheckError('Typecheck error: noise out of bounds for the expression: %s' %  self, 3)

                else:
                           raise TypecheckError('Typecheck error: value out of bounds for the expression: %s' % self, 6)
            
            elif  is_plain_type(self.t1) and is_plain_type(self.t2):
                val1, delta1 = get_plain_type_attributes(self.t1)
                val2, delta2 = get_plain_type_attributes(self.t2)
                val = val1 * val2
                delta = delta1 * delta2
                return '%s' % PlainType('plain', val, delta)
            else:
                raise RuntimeError('Typecheck error')
        elif self.op == '@':
            if is_cipher_type(self.t1) and is_cipher_type(self.t2):
                #Compute new inf and sup
                inf1, sup1, eps1, om1 = get_cipher_type_attributes(self.t1)
                inf2, sup2, eps2, om2 = get_cipher_type_attributes(self.t2)
                logq, t, d, l = self.backend.get_params(om1)
                inf = inf1 + inf2
                sup = sup1 + sup2
                # Both supremum and canonical norm has same computation
                eps = eps1 + eps2

                if om1 == om2:
                     #Check if new and sup are within the range of t
                     if func_correct:
                         if (-t/2 <= inf <= sup < t/2):
                         # check if eps is within noise bound
                             if ( eps <= l):
                                 return '%s' % CipherType('cipher', sup, inf, eps, om1)
                             else:
                               raise TypecheckError('Typecheck error: noise out of bounds for the expression: %s' %  self, 3)

                         else:
                           raise TypecheckError('Typecheck error: value out of bounds for the expression: %s' % self, 6)
                     else:
                         # check if eps is within noise bound
                         if ( eps <= l):
                             return '%s' % CipherType('cipher',sup, inf, eps)
                         else:
                               raise TypecheckError('Typecheck error: noise out of bounds for the expression: %s' %  self, 3)

                else:
                    raise RuntimeError('Mismatched levels %s\n' % self)

            elif  is_plain_type(self.t1) and is_cipher_type(self.t2):
                #Compute new inf and sup
                val, delta = get_plain_type_attributes(self.t1)
                inf1, sup1, eps1, om1 = get_cipher_type_attributes(self.t2)
                logq, t, d, l = self.backend.get_params(om1)
                inf = inf1 + val
                sup = sup1 + val
                eps = eps1 + delta
            
                #Check if new and sup are within the range of t
                if (-t/2 <= inf <= sup < t/2):
                    # check if eps is within noise bound
                    if ( eps <= l):
                        return '%s' % CipherType('cipher',sup, inf, eps, om1)
                    else:
                               raise TypecheckError('Typecheck error: noise out of bounds for the expression: %s' %  self, 3)

                else:
                           raise TypecheckError('Typecheck error: value out of bounds for the expression: %s' % self, 6)
                
            elif  is_cipher_type(self.t1) and is_plain_type(self.t2):
                #Compute new inf and sup
                val, delta = get_plain_type_attributes(self.t2)
                inf1, sup1, eps1, om1 = get_cipher_type_attributes(self.t1)
                logq, t, d, l = self.backend.get_params(om1)
                inf = inf1 + val
                sup = sup1 + val
                eps = eps1 + delta
            
                #Check if new and sup are within the range of t
                if (-t/2 <= inf <= sup < t/2):
                    # check if eps is within noise bound
                    if (eps <= l):
                        return '%s' % CipherType('cipher',sup, inf, eps, om1)
                    else:
                               raise TypecheckError('Typecheck error: noise out of bounds for the expression: %s' %  self, 3)
                else:
                           raise TypecheckError('Typecheck error: value out of bounds for the expression: %s' % self, 6)
            
            elif  is_plain_type(self.t1) and is_plain_type(self.t2):
                val1, delta1 = get_plain_type_attributes(self.t1)
                val2, delta2 = get_plain_type_attributes(self.t2)
                val = val1 + val2
                delta = delta1 + delta2
                return '%s' % PlainType('plain', val, delta)
            else:
                raise TypecheckError('Non-homomorphic operation\n', 8)

        else:
               raise TypecheckError('Typecheck error: Unknown operator', 9)
           
    def typecheck(self, gamma):
        return self.typecheck(gamma)

    def typecheck_relaxed(self, gamma):
        t1 = self.left.typecheck_relaxed(gamma)
        t2 = self.right.typecheck_relaxed(gamma)
        #logq, t, d, l = self.backend.get_params()
        qlist = self.backend.get_modulus_chain()
        ql = qlist[:-1]
        norm_ty = self.backend.get_norm_type()
        if self.op == '&':
            if is_cipher_type(t1) and is_cipher_type(t2):
                #Compute new inf and sup
                inf1, sup1, eps1, om1 = get_cipher_type_attributes(t1)
                inf2, sup2, eps2, om2 = get_cipher_type_attributes(t2)
                logq, t, d, l = self.backend.get_params(om1)
                inf = min([inf1*inf2, inf1*sup2, inf2*sup1, sup1*sup2])
                sup = max([inf1*inf2, inf1*sup2, inf2*sup1, sup1*sup2])
                
                if norm_ty == 1:
                   # supremum norm
                   # raw noise multiplication---very inefficient.
                   eps = eps1 * eps2
                   # # SEAL noise estimation: t * sqrt(3) * d * (v1 + v2 +1) + k
                   # two_pow = pow(2, 60)
                   # m = 19.2 * 8192 * two_pow * (1 + math.log(2*l, two_pow))
                   # k = t/l * m
                   # eps = t  * 6 * d * (eps1 + eps2 + math.sqrt(12 * d)) + k
                elif norm_ty ==2:
                    #canonical norm multiplicative noise
                    eps = eps1 * eps2 + (77 * math.sqrt(d))
                elif norm_ty == 3:
                    #canonical norm multiplicative noise
                    eps = eps1 * eps2 + (77 * math.sqrt(d))
                else:
                    raise RuntimeError('Relaxed Typecheck Error: Unknown norm\n')
                
                if om1 == om2:
                   #Check if new and sup are within the range of t
                   if func_correct:
                       if (-t/2 <= inf <= sup < t/2):
                           # check if eps/ql is within noise bound
                           f = eps // ql
                           if ( f <= l):
                               return '%s' % CipherType('cipher',sup, inf, eps, om1)
                           else:
                               raise RuntimeError('Relaxed Typecheck error: noise out of bounds for the expression: %s' %  self)
                       else:
                           raise RuntimeError('Relaxed Typecheck error: value out of bounds for the expression: %s' % self)
                   else:
                           # check if eps is within noise bound
                           if ( eps <= l):
                               return '%s' % CipherType('cipher',sup, inf, eps, om1)
                           else:
                               raise RuntimeError('Relaxed Typecheck error: noise out of bounds for the expression: %s' %  self)
                else:
                    raise RuntimeError('Relaxed Typecheck error: Mismatched levels %s\n' % self)
                
            elif  is_plain_type(t1) and is_cipher_type(t2):
                #Compute new inf and sup
                val, delta = get_plain_type_attributes(t1)
                inf1, sup1, eps1, om1 = get_cipher_type_attributes(t2)
                logq, t, d, l = self.backend.get_params(om1)
                inf = inf1 * val
                sup = sup1 * val
                eps = eps1 * delta
            
                #Check if new and sup are within the range of t
                if (-t/2 <= inf <= sup < t/2):
                    f = eps//ql
                    # check if eps is within noise bound
                    if ( f <= l):
                        return '%s' % CipherType('cipher',sup, inf, eps, om1)
                    else:
                        raise RuntimeError('Relaxed Typecheck error: noise out of bounds')
                else:
                    raise RuntimeError('Relaxed Typecheck error: value out of bounds')
            elif  is_cipher_type(t1) and is_plain_type(t2):
                #Compute new inf and sup
                val, delta = self.get_plain_type_attributes(t2)
                inf1, sup1, eps1, om1 = self.get_cipher_type_attributes(t1)
                logq, t, d, l = self.backend.get_params(om1)
                inf = inf1 * val
                sup = sup1 * val
                eps = eps1 * delta
            
                #Check if new and sup are within the range of t
                if (-t/2 <= inf <= sup < t/2):
                    # check if eps is within noise bound
                    if ( eps <= l):
                        return '%s' % CipherType('cipher',sup, inf, eps, om1)
                    else:
                        raise RuntimeError('Relaxed Typecheck error: noise out of bounds')
                else:
                    raise RuntimeError('Relaxed Typecheck error: value out of bounds')
            
            elif  is_plain_type(t1) and is_plain_type(t2):
                val1, delta1 = get_plain_type_attributes(t1)
                val2, delta2 = get_plain_type_attributes(t2)
                val = val1 * val2
                delta = delta1 * delta2
                return '%s' % PlainType('plain', val, delta)
            else:
                raise RuntimeError('Relaxed Typecheck error')
        elif self.op == '@':
            if is_cipher_type(t1) and is_cipher_type(t2):
                #Compute new inf and sup
                inf1, sup1, eps1, om1 = get_cipher_type_attributes(t1)
                inf2, sup2, eps2, om2 = get_cipher_type_attributes(t2)
                logq, t, d, l = self.backend.get_params(om1)
                inf = inf1 + inf2
                sup = sup1 + sup2
                # Both supremum and canonical norm has same computation
                eps = eps1 + eps2

                if om1 == om2:
                     #Check if new and sup are within the range of t
                     if func_correct:
                         if (-t/2 <= inf <= sup < t/2):
                             f = eps//ql
                         # check if eps is within noise bound
                             if ( f <= l):
                                 return '%s' % CipherType('cipher', sup, inf, eps, om1)
                             else:
                                 raise RuntimeError('Relaxed Typecheck error: noise out of bounds')
                         else:
                             raise RuntimeError('Relaxed Typecheck error: value out of bounds')
                     else:
                         # check if eps is within noise bound
                         if ( eps <= l):
                             return '%s' % CipherType('cipher',sup, inf, eps)
                         else:
                             raise RuntimeError('Relaxed Typecheck error: noise out of bounds')
                else:
                    raise RuntimeError('Relaxed Mismatched levels %s\n' % self)

            elif  is_plain_type(t1) and is_cipher_type(t2):
                #Compute new inf and sup
                val, delta = get_plain_type_attributes(t1)
                inf1, sup1, eps1, om1 = get_cipher_type_attributes(t2)
                logq, t, d, l = self.backend.get_params(om1)
                inf = inf1 + val
                sup = sup1 + val
                eps = eps1 + delta
            
                #Check if new and sup are within the range of t
                if (-t/2 <= inf <= sup < t/2):
                    f = (eps1//ql) + delta
                    # check if eps is within noise bound
                    if ( f <= l):
                        return '%s' % CipherType('cipher',sup, inf, eps, om1)
                    else:
                        raise RuntimeError('Relaxed Typecheck error: noise out of bounds')
                else:
                    raise RuntimeError('Relaxed Typecheck error: value out of bounds')
                
            elif  is_cipher_type(t1) and is_plain_type(t2):
                #Compute new inf and sup
                val, delta = get_plain_type_attributes(t2)
                inf1, sup1, eps1, om1 = get_cipher_type_attributes(t1)
                logq, t, d, l = self.backend.get_params(om1)
                inf = inf1 + val
                sup = sup1 + val
                eps = eps1 + delta
            
                #Check if new and sup are within the range of t
                if (-t/2 <= inf <= sup < t/2):
                    f = (eps1//ql) + delta
                    # check if eps is within noise bound
                    if (f <= l):
                        return '%s' % CipherType('cipher',sup, inf, eps, om1)
                    else:
                        raise RuntimeError('Relaxed Typecheck error: noise out of bounds')
                else:
                    raise RuntimeError('Relaxed Typecheck error: value out of bounds')
            
            elif  is_plain_type(t1) and is_plain_type(t2):
                val1, delta1 = get_plain_type_attributes(t1)
                val2, delta2 = get_plain_type_attributes(t2)
                val = val1 + val2
                delta = delta1 + delta2
                return '%s' % PlainType('plain', val, delta)
            else:
                raise RuntimeError('Relaxed Typecheck error')

        else:
               raise RuntimeError('Relaxed Typecheck error: Unknown operator')
           
        
    def ms_infer(self, gamma_rel, gamma, insert):
        newexpty = self.typecheck(gamma)
        #insert modswitch only for multiplication where at least operand is cipher
        if self.op == '&' and (is_cipher_type(self.t1) or is_cipher_type(self.t2)):
            newexp = UnaryopPexp('ms', self, self.backend)
            newexpty = newexp.typecheck(gamma)
            return newexp, True, newexpty
        else:
            return self, False, newexpty
 
    def levelizer(self, gamma):
        if self.op == '&':
            llevel = get_level(self.left, gamma, self.backend)
            rlevel = get_level(self.right, gamma, self.backend)
            newexp = None
            if llevel != rlevel:
                if (llevel < rlevel):
                    diff = rlevel - llevel
                    newexp = self.right
                else:
                    diff = llevel - rlevel
                    newexp = self.left
                    while (diff > 0):
                        newexp= self.UnaryopExp('ms', newexp, self.backend)
                        diff = diff -1
                return newexp
            else:
                return self
        else:
            # no ms insertions necessary for other operators.
            return self
              
class BinopVexp(Vexp):
    def __init__(self, op, left, right, bgv):
        self.op = op
        self.left = left
        self.right = right
        self.bgv = bgv
        self.t1 = None
        self.t2 = None

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

    def compile(self):
        pass
    

    def eval(self, env):
        left_value = self.left.eval(env)
        right_value = self.right.eval(env)
        vec_tag = 3
        size = (0,0)
        if self.op == '*':
            if left_value.tag == 3 and right_value.tag == 3:
                v = self.bgv.vec_mult(left_value.v, right_value.v)
            elif left_value.tag == 4 and right_value.tag == 3:
                v = self.bgv.vec_plain_mult(right_value.v, left_value.v)
            elif left_value.tag == 3 and right_value.tag == 4:
                v = self.bgv.vec_plain_mult(left_value.v, right_value.v)
            else:
                v = self.bgv.plain_mult(left_value.v, right_value.v)
                vec_tag = 2
                
        elif self.op == '+':
            if left_value.tag == 3 and right_value.tag == 3:
                v = self.bgv.cipher_add(left_value.v, right_value.v)
            elif left_value.tag == 4 and right_value.tag == 3:
                v = self.bgv.cipher_plain_add(right_value.v, left_value.v)
            elif left_value.tag == 3 and right_value.tag == 4:
                v = self.bgv.cipher_plain_add(left_value.v, right_value.v)
            else:
                v = self.bgv.plain_add(left_value.v, right_value.v)
                vec_tag = 2
        elif self.op == '$':
            if left_value.tag == 5 and right_value.tag == 5:
                v = self.bgv.cipher_mat_mult(left_value.v, right_value.v)
                (lrows, _) = left_value.size
                (_, rcol) = right_value.size
                size = (lrows, rcol)
                vec_tag = 5
            elif left_value.tag == 6 and right_value.tag == 5:
                v = self.bgv.cipher_plain_mat_mult(right_value.v, left_value.v)
            elif left_value.tag == 5 and right_value.tag == 6:
                v = self.bgv.cipher_plain_mat_mult(left_value.v, right_value.v)
            else:
                v = self.bgv.plain_add(left_value.v, right_value.v)
                vec_tag = 2
        else:
            raise RuntimeError('unknown operator: ' + self.op)
        return VecValue(v, tag = vec_tag, size = size, length=left_value.length )#, self.left.length)

