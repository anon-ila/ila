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

import lexer

RESERVED = 'RESERVED'
INT      = 'INT'
FLOAT    = 'FLOAT'
ID       = 'ID'
POLY     = 'POLY'

token_exprs = [
    (r'[ \n\t]+',              None),
    (r'#[^\n]*',               None),
    (r'(\-)?[0-9]+(\.[0-9]+)?',  FLOAT),
    (r'\.',                   RESERVED),
    (r'\^',                   RESERVED),
    (r'\"',                   RESERVED),
    (r'\-',                   RESERVED),
    (r'\:=',                   RESERVED),
    (r'\:',                   RESERVED),
    (r'\(',                    RESERVED),
    (r'\)',                    RESERVED),
    (r';',                     RESERVED),
    (r',',                     RESERVED),
    (r'\+',                    RESERVED),
    (r'-',                     RESERVED),
    (r'\$',                     RESERVED),
    (r'#',                     RESERVED),
    (r'\*',                    RESERVED),
    (r'\&',                    RESERVED),
    (r'\@',                    RESERVED),
    (r'/',                     RESERVED),
    (r'<=',                    RESERVED),
    (r'<',                     RESERVED),
    (r'>=',                    RESERVED),
    (r'>',                     RESERVED),
    (r'!=',                    RESERVED),
    (r'=',                     RESERVED),
    (r'\[',                     RESERVED),
    (r'\]',                     RESERVED),
    (r'index',                   RESERVED),
    (r'and',                   RESERVED),
    (r'or',                    RESERVED),
    (r'not',                   RESERVED),
    (r'if',                    RESERVED),
    (r'then',                  RESERVED),
    (r'else',                  RESERVED),
    (r'while',                 RESERVED),
    (r'do',                    RESERVED),
    (r'end',                   RESERVED),
    (r'startdecl',                  RESERVED),
    (r'vec',                  RESERVED),
    (r'minit',                  RESERVED),
    (r'matrix',                  RESERVED),
    (r'cipher',                  RESERVED),
    (r'plain',                  RESERVED),
    (r'cpolyinit',                  RESERVED),
    (r'cinit',                  RESERVED),
    (r'pinit',                  RESERVED),
    (r'vinit',                  RESERVED),
    (r'modswitch',                  RESERVED),
    (r'envinit',                  RESERVED),
    (r'int',                  RESERVED),
    (r'[0-9]+',                INT),
    (r'[A-Za-z][A-Za-z0-9_]*', ID),
    (r'x\^[0-9]', POLY),
]

def ila_lex(characters):
    return lexer.lex(characters, token_exprs)
