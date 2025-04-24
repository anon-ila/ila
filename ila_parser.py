# Copyright (c) 2011, Jay Conrod.
# All rights reserved.

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of Jay Conrod nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.

# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL JAY CONROD BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from ila_lexer import *
from combinators import *
from ila_ast import *
from functools import reduce

# FIXME: Global seal, openfhe
#seal = Seal(1)
#openfhe = OpenFHE(1)
#tfhers = TFHErs(3)
# backend = Backend(1)

# Basic parsers
def keyword(kw):
    return Reserved(kw, RESERVED)

num = Tag(INT) ^ (lambda i: int(i))
rational = Tag(FLOAT) ^ (lambda f: float(f))
id = Tag(ID)
poly = Tag(POLY)

# Top level parser
def ila_parse(tokens, bkend, sch_ty):
    global backend
    global scheme_ty
    scheme_ty = sch_ty
    backend = Backend(scheme_ty)
    if bkend == 1:
        backend = Seal(scheme_ty)
    elif bkend == 2:
        backend = OpenFHE(scheme_ty)
    elif bkend == 3:
        backend = TFHErs(scheme_ty)
        
    ast = parser()(tokens, 0)
    return ast, backend

def parser():
    try:
        v = Phrase(type_list_section())
        return v
    except:
        raise
        

# Type declaration
def type_list_section():
#    return keyword('startdecl') + type_list() + keyword('end') + stmt_list()
    ty_li = type_list()
    st_li = stmt_list()
    if ty_li == None:
        sys.std.write('Need atleast one variable\n')
    if st_li == None:
        sys.std.write('Need atleast one statement\n')
    return  ty_li + st_li

def type_list():
    separator = keyword(';') ^ (lambda x: lambda l, r: CompoundDecl(l, r))
    return Exp(declare_type(), separator)

# Types
def declare_type():
    def process(parsed):
        ((name, _), t) = parsed
        return Declare_Type(name, t)
    return id + keyword(':') + ila_type() ^ process

def ila_type():
    def process(parsed):
         tyname = parsed
         return IlaType(tyname)
    return ila_cipher_type() | ila_plain_type() | ila_vector_type() | ila_matrix_type() | ila_integer_type() ^ process

def ila_integer_type():
    def process(parsed):
        tyname = parsed
        return IlaInteger()
    return keyword('int') ^ process

def ila_type_no_vec():
    def process(parsed):
         tyname = parsed
         return IlaType(tyname)
    return ila_cipher_type() | ila_plain_type() ^ process #| ila_integer_type()

def ila_sort():
    def process(parsed):
         tyname = parsed
         return IlaType(tyname)
    return ila_cipher_sort() | ila_plain_sort() ^ process #| ila_integer_type()

def ila_cipher_sort():
    def process(parsed):
        return parsed
    return keyword('cipher') ^ process

def ila_plain_sort():
    def process(parsed):
        return parsed
    return keyword('plain') ^ process

""" def ila_float_type():
    def process(parsed):
        tyname = parsed
        return ILAFloat()
    return keyword('float') ^ process """

def int_or_rational():
    return rational | num

def ila_cipher_type():
    def process(parsed):
         (tyname,  om_parsed) = parsed
         om = backend.get_modulus_chain_highest_level()
         #((((((((tyname, _), inf), _), sup), _), eps), om_parsed), _) = parsed
         if om_parsed:
            ((((_, inf),_),sup),_) = om_parsed
         else:
            inf = sup = 'NaN'
         return CipherType(tyname, inf, sup, int(0), int(om), scheme_ty)
    return keyword('cipher') + Opt (keyword('<') + int_or_rational() + keyword(',') +  int_or_rational() + keyword('>'))  ^ process


def ila_plain_type():
    def process(parsed):
         (tyname,  optional) = parsed
         if optional:
            ((((_, inf),_),sup),_) = optional
         else:
             inf = sup = 0
         return PlainType(tyname, inf, sup, int(0), scheme_ty)
    return keyword('plain') + Opt( keyword('<') + int_or_rational() + keyword(',') +  int_or_rational()  + keyword('>'))  ^ process


def ila_vector_type():
    def process(parsed):
        (((((tyname,sort),len),tylist))) = parsed
        tag = 3
        if sort == 'plain':
            tag = 4
        if tylist:
            ((_, types_list),_) = tylist
            return VecType(tyname, sort, types_list, tag, length = len)
        else:
            return VecType(tyname, sort, [], tag, length = len)
    # x : vec cipher n < (,) (,) >
    # x : vec plain n < (,) (,) >
    return keyword('vec') + ila_sort() + int_or_rational() + Opt( keyword('<') + Rep (keyword('(') + int_or_rational() + keyword(',') + keyword(')')) + keyword('>'))  ^ process


def ila_matrix_type():
    def process(parsed):
        ((((tyname, sort), rows), colmns), _) = parsed
    # FIX ME: should be vector type
    # matrix sort #rows #cols  < < (inf,sup) (,) .. (,) >  ...  < (,) (,) .. (,) > >
    # x : matrix cipher 2 3 < <(2,3) (2,5).. > <(10,2)...> .. < ...> >
        if sort == 'cipher':
            return VecType(tyname, sort, [ ], tag=5, size = (int(rows), int(colmns)))
        else:
            return VecType(tyname, sort, [ ], tag=6, size = (int(rows), int(colmns)))
    return keyword('matrix') + ila_sort() + int_or_rational() + int_or_rational() + Opt( keyword('<') + Rep(keyword('<') + Rep (keyword('(') + int_or_rational() + keyword(',') + keyword(')')) + keyword('>')) + keyword('>'))  ^ process

# Statements
def stmt_list():
    separator = keyword(';') ^ (lambda x: lambda l, r: CompoundStatement(l, r))
    return Exp(stmt(), separator)

def stmt():
    return assign_stmt() | if_stmt() | while_stmt()

def assign_stmt():
    def process(parsed):
        ((name, _), exp) = parsed
        return AssignStatement(name, exp, scheme_ty)
    return id + keyword(':=') + init_or_pexp_or_vexp() ^ process
    # return id + keyword(':=') + init_or_aexp() ^ process


def if_stmt():
    def process(parsed):
        (((((_, condition), _), true_stmt), false_parsed), _) = parsed
        if false_parsed:
            (_, false_stmt) = false_parsed
        else:
            false_stmt = None
        return IfStatement(condition, true_stmt, false_stmt)
    return keyword('if') + int_or_rational() + \
           keyword('then') + Lazy(stmt_list) + \
           Opt(keyword('else') + Lazy(stmt_list)) + \
           keyword('end') ^ process


def ila_exp():
    return pexp() | vexp() #aexp() | pexp() | bexp()

def init_or_pexp_or_vexp():
    return init_or_aexp() | vexp() 

def init_or_aexp():
    return ila_envinit()   | pexp() | ila_init() | aexp_term()

def ila_init():
    return ila_cipher_init() | ila_plain_init() | ila_vec_init() | ila_mat_init() | ila_cipher_poly_init()

def ila_envinit():
    def process(parsed):
         global backend
         backend = Backend()
         return backend
    return keyword('envinit') + keyword('(') + keyword(')') ^ process

def ila_cipher_poly_init():
    def process(parsed):
        # hard-code polynomial here
        return CipherValue("1x^3 + 2x^2 + 3x^1 + 4", backend, scheme_ty)
    # can't find a way to input polynomial. Let it be id for now.
    return keyword('cpolyinit') + keyword('(')  + id  + keyword(')') ^ process

def polynomial():
    return poly

def ila_cipher_init():
    def process(parsed):
        (((_, _), i), _) = parsed
        return CipherValue(str(i), backend, scheme_ty)
    return keyword('cinit') + keyword('(') + int_or_rational() + keyword(')') ^ process

def ila_plain_init():
    def process(parsed):
        (((_, _), i), _) = parsed
        return PlainValue(i, backend, scheme_ty)
    return keyword('pinit') + keyword('(') + int_or_rational() + keyword(')') ^ process

def ila_vec_init():
    def process(parsed):
        (((_, _), i), _) = parsed
        return VecValue(i, length= len(i), backend=backend)
    return keyword('vinit') + keyword('[') + Rep(int_or_rational()) + keyword(']') ^ process


def ila_mat_init():
    def process(parsed):
        (((_, _),i), _) = parsed
        i = [x[0][1] for x in i]
        return VecValue(i, backend = backend, size = (len(i[0]),len(i)))
    return keyword('minit') + keyword('(')  + Rep(keyword('[') + Rep(int_or_rational()) + keyword(']'))  + keyword(')') ^ process

def var_or_int():
    return exp_variable() | int_or_rational()

def exp_variable():
    return  (id  ^ (lambda v: VarAexp(v)))

def while_stmt():
    def process(parsed):
        ((((_, num), _), body), _) = parsed
        return WhileStatement(num, body)
    return keyword('while') + var_or_int() + \
           keyword('do') + \
           Lazy(stmt_list) + \
           keyword('end') ^ process

# Polynomial expressions
def pexp():
    return precedence(pexp_term(),
                      pexp_precedence_levels,
                      process_poly_binop)

def pexp_term():
    return  pexp_unary() | pexp_variable() | pexp_group() 

def pexp_unary():
    def process(parsed):
      (((_, _), e), _) = parsed
      return UnaryopPexp('ms', e, backend, scheme_ty)  
    return keyword('modswitch') + keyword('(') +  Lazy(pexp) + keyword(')') ^ process

def pexp_group():
    return keyword('(') + Lazy(pexp) + keyword(')') ^ process_group

def pexp_variable():
    return  (id  ^ (lambda v: VarPexp(v)))

def vexp():
    return precedence(vexp_term(),
                    vexp_precedence_levels,
                    process_vec_binop)

def vexp_term():
    return  vexp_unary() | vexp_variable() | vexp_index() | vexp_group() 


def vexp_unary():
    def process(parsed):
      (((_, _), e), _) = parsed
      return UnaryopPexp('ms', e, backend)  
    return keyword('modswitch') + keyword('(') +  Lazy(vexp) + keyword(')') ^ process

def pvar_or_int():
    return pexp_variable() | int_or_rational()
    
def vexp_index():
    def process(parsed):
      (((((_, _), x), _), e), _) = parsed
      return BinopVexp('idx', x, e, backend, scheme_ty)  
#    return vexp_variable() + keyword('[') +  int_or_rational() + keyword(']') ^ process
    return keyword('index') + keyword('(') + vexp_variable() + keyword(',') +  pvar_or_int() + keyword(')') ^ process

def vexp_group():
    return keyword('(') + Lazy(vexp) + keyword(')') ^ process_group

def vexp_variable():
    return  (id  ^ (lambda v: VarVexp(v)))

# Arithmetic expressions
def aexp():
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
           (id  ^ (lambda v: VarAexp(v)))

def process_binop(op):
    return lambda l, r: BinopAexp(op, l, r)

# An ILA-specific combinator for binary operator expressions (aexp, pexp and bexp)
def precedence(value_parser, precedence_levels, combine):
    def op_parser(precedence_level):
        return any_operator_in_list(precedence_level) ^ combine
    parser = value_parser * op_parser(precedence_levels[0])
    for precedence_level in precedence_levels[1:]:
        parser = parser * op_parser(precedence_level)
    return parser

# Miscellaneous functions for binary and relational operators
def process_poly_binop(op):
    return lambda l, r: BinopPexp(op, l, r, backend, scheme_ty)

def process_vec_binop(op):
    return lambda l, r: BinopVexp(op, l, r, backend, scheme_ty)


def process_group(parsed):
    ((_, p), _) = parsed
    return p

def any_operator_in_list(ops):
    op_parsers = [keyword(op) for op in ops]
    parser = reduce(lambda l, r: l | r, op_parsers)
    return parser

# Operator keywords and precedence levels
pexp_precedence_levels = [
    ['&'],
    ['@'],
]
aexp_precedence_levels = [
    ['*', '/'],
    ['+', '-'],
]
vexp_precedence_levels = [
    ['*'],
    ['+'],
    ['$']
]

bexp_precedence_levels = [
    ['and'],
    ['or'],
]
