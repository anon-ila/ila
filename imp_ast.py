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

from equality import *

class Statement(Equality):
    pass

class Aexp(Equality):
    pass

class Bexp(Equality):
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
    def __init__(self, name, aexp):
        self.name = name
        self.aexp = aexp

    def __repr__(self):
        return 'AssignStatement(%s, %s)' % (self.name, self.aexp)

    def eval(self, env):
        value = self.aexp.eval(env)
        env[self.name] = value

    def typecheck(self, gamma):
        t = self.aexp.typecheck(gamma)
        if (gamma[self.name] != t):
            return False
        else:
            return True
    
        
class CompoundStatement(Statement):
    def __init__(self, first, second):
        self.first = first
        self.second = second

    def __repr__(self):
        return 'CompoundStatement(%s, %s)' % (self.first, self.second)

    def eval(self, env):
        self.first.eval(env)
        self.second.eval(env)
        
    def typecheck(self, gamma):
        if self.first.typecheck(gamma):
            if self.second.typecheck(gamma):
                return True
        else:
            return False

class IfStatement(Statement):
    def __init__(self, condition, true_stmt, false_stmt):
        self.condition = condition
        self.true_stmt = true_stmt
        self.false_stmt = false_stmt

    def __repr__(self):
        return 'IfStatement(%s, %s, %s)' % (self.condition, self.true_stmt, self.false_stmt)

    def eval(self, env):
        condition_value = self.condition.eval(env)
        if condition_value:
            self.true_stmt.eval(env)
        else:
            if self.false_stmt:
                self.false_stmt.eval(env)

    def typecheck(self, gamma):
        t = self.condition.typecheck(gamma)
        if t == 'bool':
            if self.true_stmt.typecheck(gamma) and self.false_stmt.typecheck(gamma):
                return True
            else:
                return False
        else:
            return False

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
            
    def typecheck(self, gamma):
        return False
    
class ImpType(Type):
    def __init__(self, t):
        self.ty = t
    def __repr__(self):
        return '%s' % self.ty

class ILAInteger(ImpType):
    def __init__(self):
        self.ty = 'integer'
    def __repr__(self):
        return '%s' % self.ty
    
class ILABoolean(ImpType):
    def __init__(self):
        self.ty = 'bool'
    def __repr__(self):
        return 'bool'

class CipherType(ImpType):
    def __init__(self, tyname, inf, sup, eps):
        self.ty = tyname
        self.inf = inf
        self.sup = sup
        self.eps   = eps
    def __repr__(self):
        return 'cipher <%s, %s, %s>' % (self.inf, self.sup, self.eps)

class PlainType(ImpType):
    def __init__(self, tyname, val, delta):
        self.ty = tyname
        self.val = val
        self.delta = delta
    def __repr__(self):
        return 'plain <%s, %s>' % (self.val, self.delta)
    
    
class IntAexp(Aexp):
    def __init__(self, i):
        self.i = i

    def __repr__(self):
        return 'IntAexp(%d)' % self.i

    def eval(self, env):
        return self.i
    
    def typecheck(self, gamma):
        return '%s' % ILAInteger()

class VarAexp(Aexp):
    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return 'VarAexp(%s)' % self.name

    def eval(self, env):
        if self.name in env:
            return env[self.name]
        else:
            return 0
        
    def typecheck(self, gamma):
        return gamma[self.name]

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
        elif self.op == '&':
            value = -1
        elif self.op == '@':
            value = -1
        else:
            raise RuntimeError('unknown operator: ' + self.op)
        return value
    
    def typecheck(self, gamma):
        t1 = self.left.typecheck(gamma)
        t2 = self.right.typecheck(gamma)
        
        #ToDo: Raise an exception if t1 != t2
        return '%s' % ILAInteger()

class RelopBexp(Bexp):
    def __init__(self, op, left, right):
        self.op = op
        self.left = left
        self.right = right

    def __repr__(self):
        return 'RelopBexp(%s, %s, %s)' % (self.op, self.left, self.right)

    def eval(self, env):
        left_value = self.left.eval(env)
        right_value = self.right.eval(env)
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
