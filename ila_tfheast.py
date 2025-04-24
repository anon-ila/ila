import math
import numpy as np
from util import *

class TFHEAssignStatement():
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
        # if inf_exp == 'NaN' then inf_name = 'NaN'
        # if sup_exp == 'NaN' then sup_name = 'NaN'
        # 'NaN' <= any_rational and any_rational >= 'NaN'
        # if inf_exp <= inf_name <= sup_name <= sup_exp and
        # eps_name < eps_expr and both levels are the same.
        # if  inf_exp <= inf_name <= sup_name <= sup_exp and eps_name < eps_expr  but om_name > om_exp
        # this can be fixed with mod switching 
        (inf_name, sup_name, eps_name) = type_1
        (inf_exp, sup_exp, eps_exp) = type_2
        if eps_name > eps_exp:
            return 0
        if inf_name == 'NaN' and sup_name == 'NaN':
            return (eps_name <= eps_exp)
        if sup_exp == 'NaN' and inf_exp == 'NaN':
            return (eps_name <= eps_exp)
        elif inf_name == 'NaN':
            if sup_exp != 'Nan':
                return (sup_exp >= sup_name) and (eps_name <= eps_exp)
            else:
                return (eps_name <= eps_exp)
        elif sup_name == 'NaN':
            if sup_exp != 'NaN':
                return (inf_exp <= inf_name) and (eps_name <= eps_exp)
            else:
                return (eps_name <= eps_exp)
        elif sup_exp == 'NaN':
            return (inf_exp <= inf_name) and (eps_name <= eps_exp)
        elif inf_exp == 'NaN':
            return (sup_exp >= sup_name) and (eps_name <= eps_exp)
        if inf_exp != 'NaN' and sup_exp != 'NaN':
                if inf_name > inf_exp or sup_name < sup_exp:
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
                raise TypecheckError("cannot assign %s vec to a %s vec in %s\n" % (sort_exp, sort_name, self), 69)
            if alpha_list == []: # means we are at  VecValue
                # n = |(e_i)|
                if sort_name == 'cipher':
                    self.exp.tag = 5
                    sort_exp = sort_name
                    if rows != len(self.exp.v):
                        raise TypecheckError("type has %d rows, exp has  %d rows in %s\n" % (rows, len(self.exp.v), self), 76)
                    new_v = []
                    new_eps = []
                    for index, ele in enumerate(self.exp.v):
                        if len(ele) != colmns:
                            raise TypecheckError("type has %d columns, exp has  %d columns in %s\n" % (colmns, len(ele), self), 81)
                        new_col = []
                        new_noise = []
                        for colmn_index, colmn_ele in enumerate(ele):
                            value, noise = self.exp.backend.cipher_init(colmn_ele)
                            new_col.append(value)
                            new_noise.append(noise)
                            type_list[index][colmn_index] = (np.longdouble('NaN'),np.longdouble('NaN'),noise) 
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
                        raise TypecheckError("type has %d rows, exp has  %d rows in %s\n" % (rows, len(self.exp.i), self), 100)
                    new_v = []
                    new_eps = []
                    for index, ele in enumerate(self.exp.v):
                        if len(ele) != colmns:
                            raise TypecheckError("type has %d columns, exp has  %d columns in %s\n" % (colmns, len(ele), self), 105)
                        new_col = []
                        new_noise = []
                        for colmn_index, colmn_ele in enumerate(ele):
                            new_v = TFHEPlainValue(colmn_ele, self.exp.backend)
                            value = new_v.v
                            noise = new_v.eps
                            new_col.append(value)
                            new_noise.append(noise)
                            type_list[index][colmn_index] = [(np.longdouble('NaN'),np.longdouble('NaN'),noise)]
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
                raise TypecheckError("cannot assign %s vec to a %s vec in %s\n" % (sort_exp, sort_name, self), 127)
            if len(type_list) > 0 and len(type_list) != length_name: 
                type_list.extend([type_list[-1]] * (length_name - len(type_list)))
            if alpha_list == []: # means we are at  VecValue
                # n = |(e_i)|
                if sort_name == 'cipher':
                    self.exp.tag = 3
                    sort_exp = sort_name
                    self.exp.v, self.exp.eps = self.exp.backend.vec_init(self.exp.v, 3) #as self.exp.tag == 3
                    if len(type_list) == 0: #means type declaration is like x : vec cipher n 
                        type_list.extend([(np.longdouble('NaN'),np.longdouble('NaN'),self.exp.eps)] * length_name)
                        gamma[self.name] = type_name+";"+sort_name+";"+str(length_name)+';'+json.dumps(type_list)
                        self.exp.type_list = type_list
                        self.exp.length = length_name
                        return("", gamma)
                else:
                    self.exp.tag = 4
                    sort_exp = sort_name
                    self.exp.v, self.eps = self.exp.backend.vec_init(self.exp.v, 4 ) # as self.exp.tag == 4
                    type_list.extend([(np.longdouble('NaN'),np.longdouble('NaN'),self.exp.eps)] * length_name)
                    gamma[self.name] = type_name+";"+sort_name+";"+str(length_name)+';'+json.dumps(type_list)
                    self.exp.type_list = type_list
                    self.exp.length = length_name
                    return("", gamma)
            else:
                if sort_name != sort_exp:
                    raise TypecheckError("Vec type has both cipher and plain types %s\n" % self, 153)
                if length_name != length_exp:
                    raise TypecheckError('vec %d type has %d arguments at %s' % (length_name, len(self.exp.v) ,self.exp), 155)
                gamma[self.name] = type_exp+";"+sort_exp+";"+str(length_name)+';'+json.dumps(alpha_list)
                # FIX ME: Fill me
                return("", gamma)
        
        elif 'cipher' in gamma[self.name]:
            type_name, (inf_exp, sup_exp, eps_exp, level_exp) = self.exp.typeinfer(gamma, logq, q,t,d)
            if type_name != "cipher":
                raise TypecheckError('Exp type is' + type_name + '; expected cipher: %s\n' %  self, 163)
            (inf_name, sup_name, eps_name, _) = get_cipher_type_attributes(gamma[self.name])
            if (inf_exp == 'NaN') and (sup_exp == 'NaN'):
                self.exp.inf = inf_exp = inf_name
                self.exp.sup = sup_exp = sup_name
            #if eps_name > eps_exp:
            #    eps_exp = eps_name
                 #not self.is_sub_type((inf_name, sup_name, eps_name), (inf_exp, sup_exp, eps_exp)):
                #raise TypecheckError(self.name + ' is not a subtype in the assignment: %s\n' % self, 169)
            if eps_exp >= q/t - 1:
                noise = 1
                # raise TypecheckError(' Noise over flow: %s\n' % self, 175)
            if (inf_exp != 'NaN' and inf_exp <= -t/2) or (sup_exp != 'NaN' and sup_exp > t/2):
                raise TypecheckError(' Value over flow: %s\n' % self, 177)
            gamma[self.name] = "cipher <" + str(inf_exp)+ ", " + str(sup_exp)+ ", " + str(eps_exp) + ", " + str(level_exp) + ">"
            # print("Noise budget at test %s is %d\n" % (self , math.log2(1/2 - eps_exp)))
            return (error, gamma)
        elif 'plain' in gamma[self.name]:
            type_name, exp_type = self.exp.typeinfer(gamma, logq, q, t,d)
            if type_name != "plain":
                raise TypecheckError('Exp type is' + type_name + '; expected plain: %s\n' %  self, 180)
            (inf_name, sup_name, eps_name) = get_plain_type_attributes(gamma[self.name], scheme=1)
            if len(exp_type) == 3:
                (inf_exp, sup_exp, eps_exp) = exp_type
            else:
                (inf_exp, sup_exp, eps_exp, _ ) = exp_type
            if (inf_exp == 'NaN') and (sup_exp == 'NaN'):
                self.exp.inf = inf_exp = inf_name
                self.exp.sup = sup_exp = sup_name
            if not self.is_sub_type((inf_name, sup_name, eps_name), (inf_exp, sup_exp, eps_exp)):
                TypecheckError(self.name + ' is not a subtype in the assignment: %s\n' % self, 190)
            if eps_exp >= q/t -2:
                noise = 1
                # raise TypecheckError(' Noise over flow: %s\n' % self, 11)
            if (inf_exp != 'NaN' and inf_exp <= -t/2) or (sup_exp != 'NaN' and sup_exp > t/2):
                raise TypecheckError(' Value over flow: %s\n' % self, 11)
            gamma[self.name] = "plain <" + str(inf_exp)+ ", " + str(sup_exp)+ ", " + str(eps_exp) + ">"
            #print("Noise budget at %s is %d\n" % (self , log2(q/2 - eps_exp)))
            return (error, gamma)

    


class TFHECipherType():
    def __init__(self, tyname, inf, sup, eps):
        self.ty = tyname
        self.inf = inf
        self.sup = sup
        self.eps = eps
        self.level = 1

    def __repr__(self):
        return 'cipher <%s, %s, %s, %s>' % (self.inf, self.sup, self.eps, self.level)


class TFHEPlainType():
    def __init__(self, tyname, inf, sup, eps):
        self.ty = tyname
        self.inf = inf
        self.sup = sup
        self.eps = eps
    def __repr__(self):
        return 'plain <%s, %s, %s>' % (self.inf, self.sup, self.eps)

        
class TFHEPlainValue():
    def __init__(self, i, backend):
        # set tag to cipher
        self.tag = 2
        # call backend module
        self.v = backend.plain_init(i)
        self.eps = 0
        
    def __repr__(self):
        return 'plain %s' % self.v
    

    def compile(self):
        pass
    
    def eval(self, env):
        # Return value
        return self

    def typeinfer(self, gamma, logq, coeff_mod,plain_mod,d):
        return ('plain', ('NaN', 'NaN', self.eps))

    def typecheck(self, gamma):
        return '%s' % TFHEPlainType('plain', self.inf, self.sup)

    def typecheck_relaxed(self, gamma):
        return self.typecheck(gamma)
    

    
class TFHECipherValue():
    def __init__(self, i, backend):
        # set tag to cipher
        self.tag = 1
        self.i = str(int(float(i)))
        self.v = None
        # call backend module
        try:
            f = float(i)
            self.v, _ = backend.cipher_init(f)
        except ValueError:
            self.v, _ = backend.cipher_poly_init(i)
        _, q, t, d = backend.get_params_default()
        self.eps = 1
        #self.eps = 12 * (t/q) * (d * (t-1)/12 + 3.2 * (math.sqrt(4 * (d ** 2)/3 + d)))
        self.level = 0
            
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
    
    def typeinfer(self, gamma, logq, coeff_mod,plain_mod,d):
        return ('cipher', ('NaN', 'NaN', np.longdouble(self.eps), self.level))
    
    def typecheck(self, gamma):
        return '%s' % TFHECipherType('cipher', self.inf, self.sup, self.eps)

    def ms_infer(self, gamma_rel, gamma, insert):
        newexpty = self.typecheck(gamma)
        return self, False, newexpty

    def levelizer(self, gamma):
        return self


class TFHEUnaryopPexp():
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
        return self.backend.modswitch(val.v), 1

 
    def levelizer(self, gamma):
        return self


class TFHEBinopPexp():
    def __init__(self, op, left, right, backend):
        self.op = op
        self.left = left
        self.right = right
        self.backend = backend
        self.t1 = None
        self.t2 = None

    def __repr__(self):
        return '(%s %s %s)' % (self.left, self.op, self.right)
    
    def typeinfer(self, gamma, logq, q,t ,d):
        if "&" == self.op:
            inf = sup = None
            noise = 0
            ltyname, (linf,lsup,lnoise, llevel) = (self.left).typeinfer(gamma, logq, q,t ,d)
            rtyname, temp_list = (self.right).typeinfer(gamma, logq, q,t,d)
            (rinf,rsup,rnoise, rlevel ) = temp_list
            if ltyname == rtyname == "plain":
                raise Exception("Plain multiplication is not supported currently")
            if linf == 'NaN' or rinf == 'NaN':
                inf = 'NaN'
            if rsup == 'NaN' or lsup == 'NaN':
                sup = 'NaN'
            else:
                inf = min([linf*rinf, linf*rsup, rinf*lsup, lsup*rsup])
                sup = max([linf*rinf, linf*rsup, rinf*lsup, lsup*rsup])
            if ltyname == "plain" or rtyname == 'plain':
                noise =  lnoise + rnoise
            else:
                noise = 1
            return("cipher", (inf,sup, noise, 0))
            #return("cipher", (inf,sup, (lnoise*rnoise), level))
        if "@" == self.op:
            ltyname, (linf,lsup,lnoise, llevel) = (self.left).typeinfer(gamma, logq, q,t,d)
            rtyname, (rinf,rsup,rnoise, rlevel) = (self.right).typeinfer(gamma, logq, q,t,d)
            if ltyname == rtyname == "plain":
                raise Exception("Plain addition is not supported currently")
            inf = sup = 'NaN'
            noise = lnoise + rnoise
            if linf == 'NaN' or rinf == 'NaN':
                inf = 'NaN'
            if rsup == 'NaN' or lsup == 'NaN':
                sup = 'NaN'
            else:
                inf = linf+rinf
                sup = lsup+rsup
            return "cipher",(inf, sup, noise, 0)
            

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
        return v, tag

    def t_add_plain_cipher(self, gamma, ty1, ty2, sigma):
        pass

   
              
