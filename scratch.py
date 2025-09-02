
    def typeinfer_helper(self, expr, gamma, logq, plain_mod, degree):
            if type(expr) == CipherValue:
                inf, sup, _,_ = get_cipher_type_attributes(gamma[self.name])
                if inf < 0 or sup < 0:
                    raise Exception("Inf or Sup is negative")
                return(expr.inf-inf,expr.sup+sup, expr.eps, expr.om)
            if type(expr) == PlainValue:
                inf, sup, _ = get_plain_type_attributes(gamma[self.name])
                if inf < 0 or sup < 0:
                    raise Exception("Inf or Sup is negative")
                return(expr.inf-inf, expr.sup+sup, expr.eps, -1)
            if type(expr) == VarPexp:
                try:
                    inf, sup, noise, om = get_cipher_type_attributes(gamma[expr.name])
                except:
                    inf, sup, noise = get_plain_type_attributes(gamma[expr.name])
                    return(inf, sup, noise, -1)
                return(inf, sup, noise, om)
            if "&" == expr.op:
                (linf,lsup,lnoise,llevel) = self.typeinfer_helper(expr.left,gamma, logq, plain_mod, degree)
                (rinf,rsup,rnoise,rlevel) = self.typeinfer_helper(expr.right,gamma, logq, plain_mod, degree)
                if (llevel != -1) and (rlevel != -1) and (llevel != rlevel) :
                    raise Exception("Level mis-match at &")
                inf = min([linf*rinf, linf*rsup, rinf*lsup, lsup*rsup])
                sup = max([linf*rinf, linf*rsup, rinf*lsup, lsup*rsup])
                # relin noise = (lnoise * rnoise) + (t * d * w * \sigma * \sqrt(3) * \sqrt(ell+1))
                # ell = log q/loq w ; in seal log w is undefined.
                # assuming log w = 90   
                return(inf,sup, (lnoise*rnoise) + (plain_mod * degree * (2 ** 90) * 3.2 * math.sqrt ( logq/30 + 3)), max(llevel, rlevel))
            if "@" == expr.op:
                (linf,lsup,lnoise,llevel) = self.typeinfer_helper(expr.left,gamma, logq, plain_mod, degree)
                (rinf,rsup,rnoise,rlevel) = self.typeinfer_helper(expr.right,gamma, logq, plain_mod, degree)
                if llevel != -1 and rlevel != -1 and llevel != rlevel :
                    raise Exception("Level mis-match")
                return(linf+rinf,lsup+rsup, lnoise+rnoise,  max(llevel, rlevel))
            
    #def typeinfer_helper_vec(self, expr, gamma):
 
            
    def typeinfer_helper_plain(self, expr, gamma):
            if type(expr) == PlainValue:
                inf, sup, _ = get_plain_type_attributes(gamma[self.name])
                if inf < 0 or sup < 0:
                    raise Exception("Inf or Sup is negative")
                return(expr.inf-inf,expr.sup+sup, expr.eps)
            if type(expr) == VarPexp:
                inf, sup, eps = get_plain_type_attributes(gamma[expr.name])
                return(inf, sup, eps)
            if "&" == expr.op:
                (linf,lsup,lnoise) = self.typeinfer_helper_plain(expr.left,gamma)
                (rinf,rsup,rnoise) = self.typeinfer_helper_plain(expr.right,gamma)
                inf = min([linf*rinf, linf*rsup, rinf*lsup, lsup*rsup])
                sup = max([linf*rinf, linf*rsup, rinf*lsup, lsup*rsup])
                # relin noise = (lnoise * rnoise) + (t * d * w * \sigma * \sqrt(3) * \sqrt(ell+1))
                # ell = log q/loq w ; in seal log w is undefined.
                # assuming log w = 90
                return(inf,sup, (lnoise*rnoise))
            if "@" == expr.op:
                (linf,lsup,lnoise,llevel) = self.typeinfer_helper_plain(expr.left,gamma)
                (rinf,rsup,rnoise,rlevel) = self.typeinfer_helper_plain(expr.right,gamma)
                return(linf+rinf,lsup+rsup, lnoise+rnoise)
            
    def typeinfer_helper_vec(self, expr, gamma, type_list, logq, plain_mod, degree):
        if type(expr) == VecValue:
            if (list(filter(lambda x: 'vec' in x, type_list)) != []):
                raise TypecheckError("Vec type has vec type, use matrix type instead %s\n" % self, 5)
            res_cipher = list(filter(lambda x: 'cipher' in x, type_list))
            res_plain = list(filter(lambda x: 'plain' in x, type_list))
            length = len(type_list)
            if len(res_cipher) != length and len(res_plain) != length:
                raise TypecheckError("Vec type has both cipher and plain types %s\n" % self, 2)
            ret_typelist = []
            if res_plain == []:   
                for index, ele in enumerate(type_list):
                    inf, sup, _, _ = get_cipher_type_attributes(ele)
                    if inf < 0 or sup < 0:
                        raise Exception("Inf or Sup is negative")
                    expr.type_list.append( (expr.v[index]-inf, expr.v[index]+sup, expr.eps, expr.om))
                    ret_typelist.append("cipher <" + str(expr.v[index]-inf)+ ", " + str(expr.v[index]+sup)+ ", " + str(expr.eps)+ ", " + str(expr.om)+ ">")
                    expr.tag = 3
                return(expr.eps, ret_typelist)
            else:
                for index, ele in enumerate(type_list):
                    inf, sup, _ = get_plain_type_attributes(ele)
                    if inf < 0 or sup < 0:
                        raise Exception("Inf or Sup is negative")
                    expr.type_list.append((expr.v[index]-inf, expr.v[index]+sup, expr.noise_list[index], expr.om))
                    ret_typelist.append("plain <" + str(expr.v[index]-inf)+ ", " + str(expr.v[index]+sup)+ ", " + str(expr.noise_list[index]) + ">")
                    expr.tag = 4
                return(max(expr.noise_list),ret_typelist)
        if type(expr) == VarPexp:
                    ty_list = gamma[expr.name]
                    try:
                        eps_list = []
                        for i in ty_list:
                            _, _ , eps, _ = get_cipher_type_attributes(i)
                            eps_list.append(eps)
                        expr.tag = 3
                        #del expr.val_plain
                        gc.collect()
                        return (max(eps_list), ty_list)
                    except:
                        eps_list = []
                        for i in ty_list:
                            _, _ , eps = get_plain_type_attributes(i)
                            eps_list.append(eps)
                        expr.tag = 4
                        #del expr.val_cipher
                        gc.collect()
                        return (max(eps_list), ty_list)
        if "&" == expr.op:
                noise, llist = self.typeinfer_helper_vec(expr.left, gamma, type_list, logq, plain_mod, degree)
                noise, rlist = self.typeinfer_helper_vec(expr.right,gamma, type_list, logq, plain_mod, degree)
                if len(llist) != len(rlist):
                    raise Exception("Operation not defined on vectors of different legths &")
                ret_list = []
                noise = 0
                for index, val in enumerate(llist):
                    try:
                        linf, lsup , lnoise, llevel = get_cipher_type_attributes(val)
                    except:
                        linf, lsup , lnoise = get_plain_type_attributes(val)
                        llevel = -1
                    try:
                        rinf, rsup , rnoise, rlevel = get_cipher_type_attributes(rlist[index])
                    except:
                        rinf, rsup , rnoise = get_plain_type_attributes(rlist[index])
                        rlevel = -1
                    if (llevel != -1) and (rlevel != -1) and (llevel != rlevel) :
                        raise Exception("Level mis-match at &")
                    inf = min([linf*rinf, linf*rsup, rinf*lsup, lsup*rsup])
                    sup = max([linf*rinf, linf*rsup, rinf*lsup, lsup*rsup])
                    new_noise = plain_mod * degree * (2 ** 90) * 3.2 * math.sqrt ( logq/30 + 3)
                    if noise < new_noise:
                        noise = new_noise
                    #expr.tylist[index] = (inf, sup, new_noise, max(llevel, rlevel))
                    ret_list.append("cipher <" + str(inf)+ ", " + str(sup)+ ", " + str(new_noise)+ ", " + str(max(llevel, rlevel))+ ">")
                # relin noise = (lnoise * rnoise) + (t * d * w * \sigma * \sqrt(3) * \sqrt(ell+1))
                # ell = log q/loq w ; in seal log w is undefined.
                # assuming log w = 90 
                expr.tag = 3  
                return(noise, ret_list)
        if "@" == expr.op:
                lnoise, llist = self.typeinfer_helper_vec(expr.left, gamma, type_list, logq, plain_mod, degree)
                rnoise, rlist = self.typeinfer_helper_vec(expr.right,gamma, type_list, logq, plain_mod, degree)
                if len(llist) != len(rlist):
                    raise Exception("Operation not defined on vectors of different legths &")
                ret_list = []
                noise = 0
                # TODO add plain text overflows.
                for index, val in enumerate(llist):
                    tag = -1
                    try:
                        linf, lsup , lnoise, llevel = get_cipher_type_attributes(val)
                        tag = 1
                    except:
                        linf, lsup , lnoise = get_plain_type_attributes(val)
                        llevel = -1
                    try:
                        tag = 1
                        rinf, rsup , rnoise, rlevel = get_cipher_type_attributes(rlist[index])
                    except:
                        rinf, rsup , rnoise = get_plain_type_attributes(rlist[index])
                        rlevel = -1
                    if noise < lnoise + rnoise:
                        noise = lnoise + rnoise
                    if (llevel != -1) and (rlevel != -1) and (llevel != rlevel) :
                        raise Exception("Level mis-match at &")
                    # expr.tylist[index] = (linf+rinf, lsup+rsup, lnoise+rnoise,  max(llevel, rlevel))
                    if tag == 1:
                        ret_list.append("cipher <" + str(linf+rinf)+ ", " + str(lsup+rsup)+ ", " + str(lnoise+rnoise)+ ", " + str(max(llevel, rlevel))+ ">")
                    else: 
                        ret_list.append("plain <" + str(linf+rinf)+ ", " + str(lsup+rsup)+ ", " + str(lnoise+rnoise)+ ">")
                expr.tag = 3
                return(noise, ret_list)

    def typeinfer(self, gamma, logq, coeff_mod, plain_mod, degree):
        error = ""
        if self.exp == None:
            return error, gamma
        if "vec" in gamma[self.name]:
            # convert vec type to a list
            length, type_list = get_vec_type_list(gamma[self.name])
            if len(type_list) == 0:
                raise TypecheckError("vec has type missing  %s\n" % self, 13)
            elif len(type_list) == 1:
                type_list = [type_list[-1]] * int(length)
                if 'cipher' in gamma[self.name]:
                    inf, sup, eps, level = get_cipher_type_attributes(type_list[0])
                    gamma[self.name] = gamma[self.name][:-1]+ ("cipher <" + str(inf)+ ", " + str(sup)+ ", " + str(eps)+ ", " + str(level)+ ">") * int(length -1 ) + ">"
                else:
                    inf, sup, eps = get_plain_type_attributes(type_list[0])
                    gamma[self.name] = gamma[self.name][:-1]+ ("plain <" + str(inf)+ ", " + str(sup)+ ", " + str(eps)+ ">") * int(length -1 ) + ">"
            elif len(type_list) < length:
                type_list.extend([type_list[-1]] * int (length - len(type_list) ))
                if 'cipher' in gamma[self.name]:
                    inf, sup, eps, level = get_cipher_type_attributes(type_list[-1])
                    gamma[self.name] = gamma[self.name][:-1]+ ("cipher <" + str(inf)+ ", " + str(sup)+ ", " + str(eps)+ ", " + str(level)+ ">") * int (length - len(type_list) -1) + ">"
                else:
                    inf, sup, eps = get_plain_type_attributes(type_list[-1])
                    gamma[self.name] = gamma[self.name][:-1]+ ("plain <" + str(inf)+ ", " + str(sup)+ ", " + str(eps)+ ">") * int (length - len(type_list) -1) + ">"

            noise, infer_type = self.typeinfer_helper_vec(self.exp, gamma, type_list, logq, plain_mod, degree)
            gamma[self.name] = infer_type
            #print("inferred type is:", infer_type)
        elif "cipher" in gamma[self.name]:
            #try:
            (inf,sup, noise,level) = self.typeinfer_helper(self.exp, gamma, logq, plain_mod, degree )
            #except Exception as e:
                #return (e,11)
            gamma[self.name] = "cipher <" + str(inf)+ ", " + str(sup)+ ", " + str(noise)+ ", " + str(level)+ ">"
            if inf <  - plain_mod or sup > plain_mod:
                error = "Warning: Plaintext modulus overflow at " + self.name
        elif "plain" in gamma[self.name]:
            (inf,sup, noise) = self.typeinfer_helper_plain(self.exp, gamma)
            if (coeff_mod/2 - noise) > 0:
                # print("noise at ", self, math.log(coeff_mod/2,2)-math.log(noise,2))
                pass
            else:
                print(("Type check failed due to noise overlow at " + self.name))
                raise TypecheckError("Type check failed due to noise overlow at %s\n" % self, 13)
            if inf <  - plain_mod or sup > plain_mod:
                error = "Warning: Plaintext modulus overflow at " + self.name
            gamma[self.name] = "plain <" + str(inf)+ ", " + str(sup)+ ", " + str(noise)+ ">"
        if (coeff_mod/2 - noise) > 0:
                pass
                # print("noise at ", self, math.log(coeff_mod/2,2)-math.log(noise,2))
        else:
                print(("Type check failed due to noise overlow at " + self.name))
                raise TypecheckError("Type check failed due to noise overlow at %s\n" % self, 13)
        # print("gamma is:", gamma)
        return error, gamma
        
    #except Exception as e:
         #   raise e

    

            if "vec" in (gamma[self.name]):
            t_to_list = gamma[self.name].split(";")
            if 'cipher' in t_to_list[2]:
                self.exp.tag = 3
                exp_type, exp_length = self.exp.type_infer()
                name_length = int(t_to_list[1])
                if exp_length != name_length:
                    raise TypecheckError('Type mismatch in the assignment: %s\n' % self, 11)
                name_type = self.name.attribute
                
                

  
""" 
class IntAexp(Aexp):
    def __init__(self, i):
        self.i = i

    def __repr__(self):
        return 'IntAexp(%d)' % self.i

    def eval(self, env):
        # must return a value
        return Value(self.i, 0)

    def typecheck(self, gamma):
        return '%s' % ILAInteger()

    def typecheck_relaxed(self, gamma):
        return self.typecheck(gamma) """
    
""" class FloatAexp(Aexp):
    def __init__(self, f):
        self.f = f

    def __repr__(self):
        return 'FloatAexp(%d)' % self.f

    def eval(self, env):
        # must return a value
        return Value(self.f, 0)
    
    def typecheck(self, gamma):
        return '%s' % ILAFloat()

    def typecheck_relaxed(self, gamma):
        return self.typecheck(gamma)

class VarAexp(Aexp):
    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return '%s' % self.name

    def eval(self, env):
        if self.name in env:
            return env[self.name]
        else:
            return 0

    def typecheck(self, gamma):
        return gamma[self.name]

    def typecheck_relaxed(self, gamma):
        return self.typecheck(gamma) """
    

"""
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
            value = left_value + right_value
        elif self.op == '-':
            value = left_value - right_value
        elif self.op == '*':
            value = left_value * right_value
        elif self.op == '/':
            value = left_value / right_value
        else:
            raise RuntimeError('unknown operator: ' + self.op)
        return value
    
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
    

class RelopBexp(Bexp):
    def __init__(self, op, left, right):
        self.op = op
        self.left = left
        self.right = right

    def __repr__(self):
        return 'RelopBexp(%s, %s, %s)' % (self.op, self.left, self.right)

    def eval(self, env):
        left_value = self.left.eval(env).v
        right_value = self.right.eval(env).v
        value = bool
        if self.op == '<':
            value = left_value < right_value
        elif self.op == '<=':
            value = left_value <= right_value
        elif self.op == '>':
            value = left_value > right_value
        elif self.op == '>=':
            value = left_value >= right_value
        elif self.op == '=':
            value = left_value == right_value
        elif self.op == '!=':
            value = left_value != right_value
        else:
            raise RuntimeError('unknown operator: ' + self.op)
        return value
    
    def typecheck(self, gamma):
        t1 = self.left.typecheck(gamma)
        t2 = self.right.typecheck(gamma)

        #ToDo: Raise an exception if t1 != t2 or t1 != ILAInteger or t2 != ILAInteger
        return '%s' % ILABoolean()
    
    def typecheck_relaxed(self, gamma):
        return self.typecheck(gamma)
    

    def ms_infer(self, gamma_rel, gamma, insert):
        newexpty = self.typecheck(gamma)
        return self, False, newexpty
 
    def levelizer(self, gamma):
        return self 

class AndBexp(Bexp):
    def __init__(self, left, right):
        self.left = left
        self.right = right

    def __repr__(self):
        return 'AndBexp(%s, %s)' % (self.left, self.right)

    def eval(self, env):
        left_value = self.left.eval(env)
        right_value = self.right.eval(env)
        return left_value and right_value

    def typecheck(self, gamma):
        t1 = self.left.typecheck(gamma)
        t2 = self.right.typecheck(gamma)

        #ToDo: Raise an exception if t1 != t2 or t1 != ILABoolean or t2 != ILABoolean
        return '%s' % ILABoolean()
    
    def typecheck_relaxed(self, gamma):
        return self.typecheck(gamma)
    

    def ms_infer(self, gamma_rel, gamma, insert):
        newexpty = self.typecheck(gamma)
        return self, False, newexpty
 
    def levelizer(self, gamma):
        return self

class OrBexp(Bexp):
    def __init__(self, left, right):
        self.left = left
        self.right = right

    def __repr__(self):
        return 'OrBexp(%s, %s)' % (self.left, self.right)

    def eval(self, env):
        left_value = self.left.eval(env)
        right_value = self.right.eval(env)
        return left_value or right_value

    
    def typecheck(self, gamma):
        t1 = self.left.typecheck(gamma)
        t2 = self.right.typecheck(gamma)

        #ToDo: Raise an exception if t1 != t2 or t1 != ILABoolean or t2 != ILABoolean
        return '%s' % ILABoolean()
    
    def typecheck_relaxed(self, gamma):
        return self.typecheck(gamma)
    
    
    def ms_infer(self, gamma_rel, gamma, insert):
        newexpty = self.typecheck(gamma)
        return self, False, newexpty
 
    def levelizer(self, gamma):
        return self
    
class NotBexp(Bexp):
    def __init__(self, exp):
        self.exp = exp

    def __repr__(self):
        return 'NotBexp(%s)' % self.exp

    def eval(self, env):
        value = self.exp.eval(env)
        return not value
    
    def typecheck(self, gamma):
        ty = self.exp.typecheck(gamma)

        #ToDo: Raise an exception if ty != ILABoolean
        return '%s' % ILABoolean()
    
    def typecheck_relaxed(self, gamma):
        return self.typecheck(gamma)
    
    def ms_infer(self, gamma_rel, gamma, insert):
        newexpty = self.typecheck(gamma)
        return self, False, newexpty
 
    def levelizer(self, gamma):
        return self 
"""

""" class ILAFloat(ImpType):
    def __init__(self):
        self.ty = 'float'
    def __repr__(self):
        return '%s' % self.ty
     """
    
""" class ILAInteger(ImpType):
    def __init__(self):
        self.ty = 'integer'
    def __repr__(self):
        return '%s' % self.ty """
    
""" class ILABoolean(ImpType):
    def __init__(self):
        self.ty = 'bool'
    def __repr__(self):
        return 'bool' """

# Comment this as ILA does not support while
class WhileStatement(Statement):
    def __init__(self, condition, body):
        self.condition = condition
        self.body = body

    def __repr__(self):
        return 'WhileStatement(%s, %s)' % (self.condition, self.body)

    def eval(self, env):
        condition_value = self.condition.eval(env)
        while condition_value:
            self.body.eval(env)
            condition_value = self.condition.eval(env)
            
    """ def typecheck(self, gamma):
        return False """

    def typecheck(self, gamma):
        return False

    def typecheck_relaxed(self, gamma):
        return False
    
############ Parser ###########
    

def while_stmt():
def process(parsed):
    ((((_, condition), _), body), _) = parsed
    return WhileStatement(condition, body)
return keyword('while') + int_or_rational + \
        keyword('do') + Lazy(stmt_list) + \
        keyword('end') ^ process

# Arithmetic expressions
""" def aexp():
    return precedence(aexp_term(),
                      aexp_precedence_levels,
                      process_binop)


def aexp_term():
    return aexp_value() | aexp_group()

def aexp_group():
    return keyword('(') + Lazy(aexp) + keyword(')') ^ process_group
           
def aexp_value():
    return (num ^ (lambda i: IntAexp(i))) | \
        (rational ^ (lambda f: FloatAexp(f))) | \
           (id  ^ (lambda v: VarAexp(v))) """

    
# Boolean expressions
"""
def bexp():
    return precedence(bexp_term(),
                      bexp_precedence_levels,
                      process_logic)

def bexp_term():
    return bexp_not()   | \
           bexp_relop() | \
           bexp_group()

def bexp_not():
    return keyword('not') + Lazy(bexp_term) ^ (lambda parsed: NotBexp(parsed[1]))

def bexp_relop():
    relops = ['<', '<=', '>', '>=', '=', '!=']
    return aexp() + any_operator_in_list(relops) + aexp() ^ process_relop

def bexp_group():
    return keyword('(') + Lazy(bexp) + keyword(')') ^ process_group """


"""
def process_binop(op):
    return lambda l, r: BinopAexp(op, l, r)
 
def process_relop(parsed):
    ((left, op), right) = parsed
    return RelopBexp(op, left, right)

def process_logic(op):
    if op == 'and':
        return lambda l, r: AndBexp(l, r)
    elif op == 'or':
        return lambda l, r: OrBexp(l, r)
    else:
        raise RuntimeError('unknown logic operator: ' + op) """
