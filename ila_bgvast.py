import math
import numpy as np
import sys
from util import *

class BGVAssignStatement():
    def __init__(self, name, exp, backend, id):
        # self.name := self.exp
        self.name = name
        self.exp = exp
        self.backend = backend
        self.id = id
        
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
        if eps_name < eps_exp:
            return 0
        if inf_name == 'NaN' and sup_name == 'NaN':
            return (eps_name >= eps_exp)
        if sup_exp == 'NaN' and inf_exp == 'NaN':
            return (eps_name >= eps_exp)
        elif inf_name == 'NaN':
            if sup_exp != 'Nan':
                return (sup_exp <= sup_name) and (eps_name >= eps_exp)
            else:
                return (eps_name >= eps_exp)
        elif sup_name == 'NaN':
            if sup_exp != 'NaN':
                return (inf_exp <= inf_name) and (eps_name >= eps_exp)
            else:
                return (eps_name >= eps_exp)
        elif sup_exp == 'NaN':
            return (inf_exp >= inf_name) and (eps_name >= eps_exp)
        elif inf_exp == 'NaN':
            return (sup_exp >= sup_name) and (eps_name <= eps_exp)
        if inf_exp != 'NaN' and sup_exp != 'NaN':
                if inf_name <= inf_exp or sup_name >= sup_exp:
                    return 0
        return 1
                
                
    def typeinfer(self, def_list, gamma, logq, q,t,d):
        error = ""
        # Matrix type
        if 'int' in gamma[self.name]:
            return("", gamma)
        elif 'matrix' in gamma[self.name]:
            type_exp, sort_exp, size_exp, alpha_list = self.exp.typeinfer(def_list,gamma, logq, q,t,d)
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
                    l = self.exp.backend.get_modulus_chain_highest_level()
                    for index, ele in enumerate(self.exp.v):
                        if len(ele) != colmns:
                            raise TypecheckError("type has %d columns, exp has  %d columns in %s\n" % (colmns, len(ele), self), 2)
                        new_col = []
                        new_noise = []
                        for colmn_index, colmn_ele in enumerate(ele):
                            value, noise = self.exp.backend.cipher_init(colmn_ele)
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
                            new_v = BGVPlainValue(colmn_ele, self.exp.backend)
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

        # LHS is a vector
        elif 'vec' in gamma[self.name]:
            type_exp, sort_exp, length_exp, alpha_list = self.exp.typeinfer(def_list,gamma, logq, q,t,d)
            type_name, sort_name, length_name, type_list = get_vec_type(gamma[self.name])
            if sort_exp != sort_name and alpha_list != []:
                raise TypecheckError("cannot assign %s vec to a %s vec in %s\n" % (sort_exp, sort_name, self), 2)
            if len(type_list) > 0 and len(type_list) != length_name: 
                type_list.extend([type_list[-1]] * (length_name - len(type_list)))
            if alpha_list == []: # means we are at  VecValue
                # n = |(e_i)|
                if sort_name == 'cipher':
                    # tag is vec cipher
                    self.exp.tag = 3
                    sort_exp = sort_name
                    self.exp.v, self.exp.eps = self.exp.backend.vec_init(self.exp.v, 3) #as self.exp.tag == 3
                    if len(type_list) == 0: #means type declaration is like x : vec cipher n 
                        l = self.exp.backend.get_modulus_chain_highest_level()
                        type_list.extend([(float('NaN'),float('NaN'),self.exp.eps,l)] * length_name)
                        gamma[self.name] = type_name+";"+sort_name+";"+str(length_name)+';'+json.dumps(type_list)
                        self.exp.type_list = type_list
                        self.exp.length = length_name
                        return("", gamma)
                else:
                    # tag is vec plain
                    self.exp.tag = 4
                    sort_exp = sort_name
                    self.exp.v, self.eps = self.exp.backend.vec_init(self.exp.v, 4 ) # as self.exp.tag == 4
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

        # LHS is a cipher type
        elif 'cipher' in gamma[self.name]:
            type_name, (inf_exp, sup_exp, eps_exp, om_exp) = self.exp.typeinfer(def_list,gamma, logq, q,t,d)
            if type_name != "cipher":
                raise TypecheckError('Exp type is' + type_name + '; expected cipher: %s\n' %  self, 11)
            (inf_name, sup_name, eps_name, om_name) = get_cipher_type_attributes(gamma[self.name])
            if (inf_exp == 'NaN') and (sup_exp == 'NaN'):
                self.exp.inf = inf_exp = inf_name
                self.exp.sup = sup_exp = sup_name
            #if self.is_sub_type((inf_name, sup_name, eps_name), (inf_exp, sup_exp, eps_exp)):
            # if om_name != om_exp:
            #     if om_name > om_exp:
            #         raise TypecheckError('Level mismatch in the assignment: %s\n' % self, 13)
            #     else:
            #         raise TypecheckError('Level mismatch in the assignment: %s\n' % self, 11)
            #else:
            #    raise TypecheckError('%s is not a subtype in the assignment: \n' % self.name, 11)
            gamma[self.name] = "cipher <" + str(inf_exp)+ ", " + str(sup_exp)+ ", " + str(eps_exp)+ ", " + str(om_exp)+ ">"
            #print("Noise budget at %s is %d\n" % (self , log2(q/2 - eps_exp)))
            qlist = self.backend.get_modulus_chain()
            if qlist != None:
                q_old = 1
                for i in range (0, om_exp-1):
                    q_old = q_old * qlist[i]
            else:
                q_old = q
            if eps_exp > q_old/2:
                #raise TypecheckError(' Noise over flow: %s\n' % self, 11)
                print("Noise overflow at", self, eps_exp, q_old/2)
                raise MSInferError(self, 13, self.backend)
            if (inf_exp != 'NaN' and inf_exp <= -t/2) or (sup_exp != 'NaN' and sup_exp > t/2):
                error = "Plain text over flow"
            return (error, gamma)

        # LHS is a plain type
        elif 'plain' in gamma[self.name]:
            type_name, exp_type = self.exp.typeinfer(def_list,gamma, logq, q, t,d)
            if type_name != "plain":
                raise TypecheckError('Exp type is' + type_name + '; expected plain: %s\n' %  self, 11)
            (inf_name, sup_name, eps_name, eps_level) = get_plain_type_attributes(gamma[self.name])
            (inf_exp, sup_exp, eps_exp, level_exp) = exp_type
            if (inf_exp == 'NaN') and (sup_exp == 'NaN'):
                self.exp.inf = inf_exp = inf_name
                self.exp.sup = sup_exp = sup_name
            if not self.is_sub_type((inf_name, sup_name, eps_name), (inf_exp, sup_exp, eps_exp)):
                TypecheckError(self.name + ' is not a subtype in the assignment: %s\n' % self, 11)
            gamma[self.name] = "plain <" + str(inf_exp)+ ", " + str(sup_exp)+ ", " + str(eps_exp)+ ">"
            if eps_exp > q/2:
                #raise TypecheckError(' Noise over flow: %s\n' % self, 11)
                print("Noise overflow at", self, eps_exp, q_old/2)
                raise MSInferError(self, 13, self.backend)
            #if eps_exp > q/2:
            #    raise TypecheckError(' Noise over flow: %s\n' % self, 11)
            if (inf_exp != 'NaN' and inf_exp <= -t/2) or (sup_exp != 'NaN' and sup_exp > t/2):
                error = "Plain text over flow at" + self
            #print("Noise budget at %s is %d\n" % (self , log2(q/2 - eps_exp)))
            return (error, gamma)
        
        # LHS is a int or float type
        elif 'float' in gamma[self.name]:
            return ("", gamma)
        elif 'integer' in gamma[self.name]:
            return ("", gamma)

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
        return self.name, newexp, changed, gamma
        
    def levelizer(self, gamma):
        newexp = self.exp.levelizer(gamma)
        return self.name, newexp

    def get_modswitch_depth(self, gamma):
        vartype = gamma[self.name]
        if is_cipher_type(vartype):
            _, _, _, om = get_cipher_type_attributes(vartype)
            return om
        else:
            return 'NaN'
    


class BGVCipherType():
    def __init__(self, tyname, inf, sup, eps, om):
        self.ty = tyname
        self.inf = inf
        self.sup = sup
        self.eps = eps
        self.om = om
    def __repr__(self):
        return 'cipher <%s, %s, %s, %s>' % (self.inf, self.sup, self.eps, self.om)


class BGVPlainType():
    def __init__(self, tyname, inf, sup, eps):
        self.ty = tyname
        self.inf = inf
        self.sup = sup
        self.eps = eps
    def __repr__(self):
        return 'plain <%s, %s, %s>' % (self.inf, self.sup, self.eps)

        
class BGVPlainValue():
    def __init__(self, i, backend):
        # set tag to cipher
        self.tag = 2
        # call backend module
        self.v = backend.plain_init(i)
        _, t, d = backend.get_params(backend.get_modulus_chain_highest_level())
        tmp = ( (1/12) + ((3.2 * 3.2) * ((4 * d/3) + 1)) )
        tmp_sqrt = math.sqrt(tmp)
        self.eps = 12 * t * tmp_sqrt
        self.inf = 'NaN'
        self.sup = 'NaN'
        
    def __repr__(self):
        return 'plain %s' % self.v
    

    def compile(self):
        pass
    
    def eval(self, env):
        # Return value
        return self

    def typeinfer(self, def_list, gamma, logq, coeff_mod,plain_mod,d):
        return ('plain', ('NaN', 'NaN', self.eps, -1))

    def typecheck(self, gamma):
        return '%s' % BGVPlainType('plain', self.inf, self.sup)

    def typecheck_relaxed(self, gamma):
        return self.typecheck(gamma)
    

    
class BGVCipherValue():
    def __init__(self, i, backend):
        # set tag to cipher
        self.tag = 1
        self.i = str(int(float(i)))
        self.v = None
        # call backend module
        try:
            f = float(i)
            self.v, noise = backend.cipher_init(f)
        except ValueError:
            self.v, noise = backend.cipher_poly_init(i)

        self.om = backend.get_modulus_chain_highest_level()
        _, t, d = backend.get_params(self.om)
        tmp = d  * ( (1/12) + ((3.2 * 3.2) * ((4 * d/3) + 1)) )
        tmp_sqrt = math.sqrt(tmp)
        self.eps = 6 * t * tmp_sqrt # 6 for openfhe, 18 for seal
            
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
    
    def typeinfer(self, def_list, gamma, logq, coeff_mod,plain_mod,d):
        return ('cipher', ('NaN', 'NaN', self.eps, self.om))
    
    def typecheck(self, gamma):
        return '%s' % BGVCipherType('cipher', self.inf, self.sup, self.eps, self.om)

    def ms_infer(self, gamma_rel, gamma, insert):
        newexpty = self.typecheck(gamma)
        return self, False, newexpty

    def levelizer(self, gamma):
        return self


class BGVUnaryopPexp():
    def __init__(self, op, exp, backend, id):
        self.op = op
        self.exp = exp
        self.backend = backend
        self.id = id
        
    def __repr__(self):
        return '%s(%s)' % (self.op, self.exp)

    def typeinfer(self, def_list, gamma, logq, coeff_mod,plain_mod,d):
        if self.op == 'ms':
            tyname, (inf, sup, noise, level) = (self.exp).typeinfer(def_list, gamma, logq, coeff_mod,plain_mod,d)
            if tyname != "cipher":
                raise Exception("Only Ciphertext can be mod switched")
            q = self.backend.get_modulus_chain()
            print(q, level)
            q_old = 1
            for i in range (0,level):
                q_old = q_old * q[i]
            q_new = 1
            for i in range (0,level-1):
                q_new = q_new * q[i]
            noise = (q_new * noise/q_old) + (6 * plain_mod * math.sqrt(d  * ( (1/12) + ((3.2 * 3.2) * ((4 * d/3) + 1)) ) ))
            # source https://eprint.iacr.org/2023/783.pdf page 27
            return("cipher", (inf, sup, noise , level-1))
        else:
            raise  Exception("Only MS is supported currently")
    def compile(self):
        pass
    
    def eval(self, env):
        val = self.exp.eval(env)
        return (val.v), 1

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
                    return '%s' % BGVCipherType('cipher',sup, inf, eps1, (omega-1))
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
                    return '%s' % BGVCipherType('cipher',sup, inf, eps1, (omega-1))
                else:
                    raise RuntimeError('Relaxed modswitch typing error: noise out of bounds\n')
            else:
                raise RuntimeError('Relaxed modswitch typing error: incorrect level \n')
        else:
            raise RuntimeError('Relaxed modswitch typing error\n')

             
    def ms_infer(self, gamma_rel, gamma, insert):
        newexpty = self.typecheck(gamma)
        if insert:
            newexp = BGVUnaryopPexp('ms', self, self.backend)
            newexpty = newexp.typecheck(gamma)
            return newexp, True, newexpty
        else:
            return self, False, newexpty
 
    def levelizer(self, gamma):
        return self


class BGVBinopPexp():
    def __init__(self, op, left, right, backend, id):
        self.op = op
        self.left = left
        self.right = right
        self.backend = backend
        self.id = id
        self.t1 = None
        self.t2 = None

    def __repr__(self):
        return '(%s %s %s)' % (self.left, self.op, self.right)
    
    def typeinfer(self, def_list, gamma, logq, coeff_mod,plain_mod,d):
        if "&" == self.op:
            inf = sup = level = noise = None
            ltyname, (linf,lsup,lnoise, llevel) = (self.left).typeinfer(def_list, gamma, logq, coeff_mod,plain_mod,d)
            rtyname, (rinf,rsup,rnoise, rlevel) = (self.right).typeinfer(def_list, gamma, logq, coeff_mod,plain_mod,d)
            if ltyname == rtyname == "plain":
                raise Exception("Plain multiplication is not supported currently")
            if (llevel != -1) and (rlevel != -1) and (llevel != rlevel) :
                raise Exception("Level mis-match at &")
            if linf == 'NaN' or rinf == 'NaN':
                inf = 'NaN'
            if rsup == 'NaN' or lsup == 'NaN':
                sup = 'NaN'
            else:
                inf = min([linf*rinf, linf*rsup, rinf*lsup, lsup*rsup])
                sup = max([linf*rinf, linf*rsup, rinf*lsup, lsup*rsup])
            if llevel == -1 or rlevel == -1:
                noise = (lnoise*rnoise) 
                level = max(llevel, rlevel)
            else:
                level = llevel
                loq, _, degree = self.backend.get_params(level)
                noise = (lnoise*rnoise) # + (plain_mod * degree * 18 * (3.2 ** 90) * 3.2 * math.sqrt( loq/30 + 3))
            # relin noise = (lnoise * rnoise) + (t * d * w * \sigma * \sqrt(3) * \sqrt(ell+1))
            # ell = log q/loq w ; in seal log w is undefined.
            # assuming log w = 90   
            # print("Noise budget at %s is %d\n" % (self , log2(coeff_mod/2 - noise)))
            return("cipher", (inf,sup, noise , level))
            #return("cipher", (inf,sup, (lnoise*rnoise), level))
        if "@" == self.op:
            ltyname, (linf,lsup,lnoise,llevel) = (self.left).typeinfer(def_list,gamma, logq, coeff_mod,plain_mod,d)
            rtyname, (rinf,rsup,rnoise,rlevel) = (self.right).typeinfer(def_list,gamma, logq, coeff_mod,plain_mod,d)
            if ltyname == rtyname == "plain":
                raise Exception("Plain addition is not supported currently")
            if llevel != -1 and rlevel != -1 and llevel != rlevel :
                raise Exception("Level mis-match")
            inf = sup = noise = None
            if linf == 'NaN' or rinf == 'NaN':
                inf = 'NaN'
            if rsup == 'NaN' or lsup == 'NaN':
                sup = 'NaN'
            else:
                inf = linf+rinf
                sup = lsup+rsup
            if llevel == -1:
                noise = rnoise
            elif rlevel == -1:
                noise = lnoise
            else:
                noise = lnoise + rnoise
            print("Noise budget at %s is %d\n" % (self , math.log2(coeff_mod/2 - noise)))
            return "cipher",(inf, sup, noise,  max(llevel, rlevel))
            

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

    def typecheck(self, gamma):

        self.t1 = self.left.typecheck(gamma)
        self.t2 = self.right.typecheck(gamma)
        #logq, t, d, l = self.backend.get_params()
        #norm_ty = self.backend.get_norm_type()
        if self.op == '&':
            if is_cipher_type(self.t1) and is_cipher_type(self.t2):
                #Compute new inf and sup
                inf1, sup1, eps1, om1 = get_cipher_type_attributes(self.t1)
                inf2, sup2, eps2, om2 = get_cipher_type_attributes(self.t2)
                logq, t, d, l = self.backend.get_params(om1)
                inf = min([inf1*inf2, inf1*sup2, inf2*sup1, sup1*sup2])
                sup = max([inf1*inf2, inf1*sup2, inf2*sup1, sup1*sup2])
                eps = eps1 * eps2 + (77 * math.sqrt(d))
                
                if om1 == om2:
                   #Check if new and sup are within the range of t
                   if func_correct:
                       if (-t/2 <= inf <= sup < t/2):
                           # check if eps is within noise bound
                           if ( eps <= l):
                               return '%s' % BGVCipherType('cipher',sup, inf, eps, om1)
                           else:
                               raise TypecheckError('Typecheck error: noise out of bounds for the selfession: %s' %  self, 3)
                       else:
                           raise TypecheckError('Typecheck error: value out of bounds for the expression: %s' % self, 6)
                   else:
                           # check if eps is within noise bound
                           if ( eps <= l):
                               return '%s' % BGVCipherType('cipher',sup, inf, eps, om1)
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
                        return '%s' % BGVCipherType('cipher',sup, inf, eps, om1)
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
                        return '%s' % BGVCipherType('cipher',sup, inf, eps, om1)
                    else:
                               raise TypecheckError('Typecheck error: noise out of bounds for the expression: %s' %  self, 3)

                else:
                           raise TypecheckError('Typecheck error: value out of bounds for the expression: %s' % self, 6)
            
            elif  is_plain_type(self.t1) and is_plain_type(self.t2):
                val1, delta1 = get_plain_type_attributes(self.t1)
                val2, delta2 = get_plain_type_attributes(self.t2)
                val = val1 * val2
                delta = delta1 * delta2
                return '%s' % BGVPlainType('plain', val, delta)
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
                                 return '%s' % BGVCipherType('cipher', sup, inf, eps, om1)
                             else:
                               raise TypecheckError('Typecheck error: noise out of bounds for the expression: %s' %  self, 3)

                         else:
                           raise TypecheckError('Typecheck error: value out of bounds for the expression: %s' % self, 6)
                     else:
                         # check if eps is within noise bound
                         if ( eps <= l):
                             return '%s' % BGVCipherType('cipher',sup, inf, eps)
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
                        return '%s' % BGVCipherType('cipher',sup, inf, eps, om1)
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
                        return '%s' % BGVCipherType('cipher',sup, inf, eps, om1)
                    else:
                               raise TypecheckError('Typecheck error: noise out of bounds for the expression: %s' %  self, 3)
                else:
                           raise TypecheckError('Typecheck error: value out of bounds for the expression: %s' % self, 6)
            
            elif  is_plain_type(self.t1) and is_plain_type(self.t2):
                val1, delta1 = get_plain_type_attributes(self.t1)
                val2, delta2 = get_plain_type_attributes(self.t2)
                val = val1 + val2
                delta = delta1 + delta2
                return '%s' % BGVPlainType('plain', val, delta)
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
        if self.op == '&':
            if is_cipher_type(t1) and is_cipher_type(t2):
                #Compute new inf and sup
                inf1, sup1, eps1, om1 = get_cipher_type_attributes(t1)
                inf2, sup2, eps2, om2 = get_cipher_type_attributes(t2)
                logq, t, d, l = self.backend.get_params(om1)
                inf = min([inf1*inf2, inf1*sup2, inf2*sup1, sup1*sup2])
                sup = max([inf1*inf2, inf1*sup2, inf2*sup1, sup1*sup2])
                eps = eps1 * eps2 + (77 * math.sqrt(d))
                
                if om1 == om2:
                   #Check if new and sup are within the range of t
                   if func_correct:
                       if (-t/2 <= inf <= sup < t/2):
                           # check if eps/ql is within noise bound
                           f = eps // ql
                           if ( f <= l):
                               return '%s' % BGVCipherType('cipher',sup, inf, eps, om1)
                           else:
                               raise RuntimeError('Relaxed Typecheck error: noise out of bounds for the expression: %s' %  self)
                       else:
                           raise RuntimeError('Relaxed Typecheck error: value out of bounds for the expression: %s' % self)
                   else:
                           # check if eps is within noise bound
                           if ( eps <= l):
                               return '%s' % BGVCipherType('cipher',sup, inf, eps, om1)
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
                        return '%s' % BGVCipherType('cipher',sup, inf, eps, om1)
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
                        return '%s' % BGVCipherType('cipher',sup, inf, eps, om1)
                    else:
                        raise RuntimeError('Relaxed Typecheck error: noise out of bounds')
                else:
                    raise RuntimeError('Relaxed Typecheck error: value out of bounds')
            
            elif  is_plain_type(t1) and is_plain_type(t2):
                val1, delta1 = get_plain_type_attributes(t1)
                val2, delta2 = get_plain_type_attributes(t2)
                val = val1 * val2
                delta = delta1 * delta2
                return '%s' % BGVPlainType('plain', val, delta)
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
                                 return '%s' % BGVCipherType('cipher', sup, inf, eps, om1)
                             else:
                                 raise RuntimeError('Relaxed Typecheck error: noise out of bounds')
                         else:
                             raise RuntimeError('Relaxed Typecheck error: value out of bounds')
                     else:
                         # check if eps is within noise bound
                         if ( eps <= l):
                             return '%s' % BGVCipherType('cipher',sup, inf, eps)
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
                        return '%s' % BGVCipherType('cipher',sup, inf, eps, om1)
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
                        return '%s' % BGVCipherType('cipher',sup, inf, eps, om1)
                    else:
                        raise RuntimeError('Relaxed Typecheck error: noise out of bounds')
                else:
                    raise RuntimeError('Relaxed Typecheck error: value out of bounds')
            
            elif  is_plain_type(t1) and is_plain_type(t2):
                val1, delta1 = get_plain_type_attributes(t1)
                val2, delta2 = get_plain_type_attributes(t2)
                val = val1 + val2
                delta = delta1 + delta2
                return '%s' % BGVPlainType('plain', val, delta)
            else:
                raise RuntimeError('Relaxed Typecheck error')

        else:
               raise RuntimeError('Relaxed Typecheck error: Unknown operator')
           
        
    def ms_infer(self, gamma_rel, gamma, insert):
        newexpty = self.typecheck(gamma)
        #insert modswitch only for multiplication where at least operand is cipher
        if self.op == '&' and (is_cipher_type(self.t1) or is_cipher_type(self.t2)):
            newexp = BGVUnaryopPexp('ms', self, self.backend)
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
                        newexp= self.BGVUnaryopExp('ms', newexp, self.backend)
                        diff = diff -1
                return newexp
            else:
                return self
        else:
            # no ms insertions necessary for other operators.
            return self
              
