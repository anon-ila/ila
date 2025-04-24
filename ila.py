#!/usr/bin/env python


import sys
import time
from ila_parser import *
from ila_lexer import *
# import gc
import subprocess

def usage():
    sys.stderr.write('Usage: ila <backend> <scheme_type> <filename>\n')
    sys.stderr.write('\t where backend = {seal, openfhe, tfhe-rs}\n')
    sys.stderr.write('\t \t \t 1 = use seal backend\n')
    sys.stderr.write('\t \t \t 2 = use openfhe backend\n')
    sys.stderr.write('\t \t \t 3 = use tfhe-rs backend\n')
    sys.stderr.write('\t where scheme_type = {bgv, bfv, tfhe}\n')
    sys.stderr.write('\t \t \t 1 = use BGV \n')
    sys.stderr.write('\t \t \t 2 = use BFV \n')
    sys.stderr.write('\t \t \t 3 = use TFHE \n')
    sys.exit(1)

def compile_prelude(f):
    f.write("use tfhe::shortint::prelude::*;\n\n")
    f.write("use tfhe::shortint::parameters::NoiseLevel;\n\n")
    f.write("fn main() {\n\n")
    f.write("// We generate a set of client/server keys\n")
    f.write("let (client_key, server_key) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);\n")
    
def compile_epilogue(f):
    #f.write("let x = ct_3.noise_level().get();\n")
    #f.write("assert_eq!(ct_3.noise_level(), NoiseLevel::ZERO);\n")
    f.write("}")
    
def decrypt_or_decode(fv):
    if fv.tag == 0:
        return fv.v, 0
    elif fv.tag == 1:
        return backend.decrypt(fv.v)
    elif fv.tag == 2:
#        return backend.decode(fv.v)
        return fv.v, 0
    elif fv.tag == 3:
        return (backend.decrypt(fv.v[0], fv.length))
    elif fv.tag == 4:
        return (backend.decode(fv.v[0], fv.length), 0)
    elif fv.tag == 5:
        return (backend.vec_decrypt(fv.v, fv.size))
    else:
        raise RuntimeError('Unknown value tag')

def print_error_codes():
    error_messages = {
        3: 'Noise out of bounds\n',
        6: 'Value out of bounds\n',
        7: 'Operation between mismatched levels\n',
        13: 'Noise comparison fails in the subtyping\n',
        15: 'Omega levels mismatched in the subtype\n',
        }
    sys.stdout.write('==================================\n')
    sys.stdout.write('Error Diagnostics for Reference:\n')
    sys.stdout.write('\t ***** \n')
    for k, v in error_messages.items():
        sys.stdout.write('%s: %s' % (str(k), v))
        
    sys.stdout.write('==================================\n')
    
def ms_infer(t, gamma_rel, gamma, qlist):
    tnew = t
    gammanew = gamma
    for x in qlist:
        changed = True
        om = tnew.get_modswitch_depth(gammanew)
        while changed:
            tnew, changed, gammanew = tnew.ms_infer(gamma_rel, gammanew, om)
            try:
                ty_stat = tnew.typecheck(gammanew)
                if ty_stat:
                    return tnew
            except Exception as e:
                    continue
    raise RuntimeError('Modswitch inference failed.\n')
        
if __name__ == '__main__':
    # usage: ila.py <backend> <scheme>  <filename>
    if len(sys.argv) != 4:
        usage()
        
    backend = int(sys.argv[1])
    scheme_ty = sys.argv[2]
    filename = sys.argv[3]

    # read input file
    text = open(filename).read()
    tokens = ila_lex(text)
    try:
        parse_result = ila_parse(tokens, backend, scheme_ty)
    except TypecheckError as e:
        sys.stdout.write ('%s' %e)
        sys.exit(1)
            
    ast, backend = parse_result[0].value, parse_result[1] 
    logq, coeff_mod, plain_mod, degree = backend.get_params_default()
    env = {}
    gamma = {}
    ast[0].eval(gamma)
    ms_infer_required = False

    sys.stdout.write('Variable types:\n')
    #for name in gamma:
    #    sys.stdout.write('%s: %s\n' % (name, gamma[name]))
    err = ""
    start_time = time.perf_counter()
    for i in range (0, 1000):
        
        try:
            # run type checker on the ast
            # sys.stdout.write('\nType infering ...\n')
            error, gamma = ast[1].typeinfer(gamma, logq, coeff_mod, plain_mod, degree )
            sys.stdout.write('Type infer passed')
            sys.stdout.write('\n*****************************************\n')
            if error != "":
                print(error)
    #        ast[1].typecheck(gamma)
        except Exception as e:
            err = e
            #sys.stdout.write('==================================\n')
            #sys.stdout.write('%s\n' % e)
            #sys.stdout.write('Returned error code: %s\n' % e.error_code)
            #ys.stdout.write('==================================\n')
            #code = e.error_code
            #if code == 3 or code == 13:
            #    ms_infer_required = True

    #print("Types after inference", gamma)
    end_time = time.perf_counter()
    execution_time = (end_time - start_time)/1000

    print(f"Execution time: " + '{:.10f}'.format(execution_time) + " seconds\n")
    print(err)

    if (scheme_ty == 3): #change to '3'
        # compile to TFHE-rs
        subprocess.run(["rm", "-rf", "output"])
        subprocess.run(["cargo", "new", "output", "--bin"])
        f = open("output/Cargo.toml", "a")
        f.write("\ntfhe = { version = \"*\", features = [\"boolean\", \"shortint\", \"integer\"] }\n")
        f.close()
        f = open("output/src/main.rs", "w")
        compile_prelude(f)
        s = ast[1].compile()
        f.write(s)

        # ideally, decrypt all encrypted vars
        # but that requires some way of collecting all vars
        compile_epilogue(f)
        #close file
        f.close()
    else:
        ast[1].eval(env)
        #print env
        sys.stdout.write('\nEvaluating ILA Program ...\n')
        sys.stdout.write('Final variable values:\n')
        for name in env:
            p = env[name]
            if isinstance(p, VecValue):
                # iterate through the vector
                for v in p.v:
                    if p.tag == 3:
                        val, noise =  decrypt_or_decode(Value(v, 1))
                    elif p.tag == 4:
                        val, noise =  decrypt_or_decode(Value(v, 2))
                    sys.stdout.write('%s: %s (remaining noise budget: %s)\n' % (name, val, noise))
            elif isinstance(p, Value):
                # Cipher value
                if p.tag == 1 or p.tag == 2:
                    val, noise =  decrypt_or_decode(p)
                    sys.stdout.write('%s: %s (remaining noise budget: %s)\n' % (name, val, noise))
                elif p.tag == 0:
                    # plain int
                    sys.stdout.write('%s: %s)\n' % (name, p.v))
            else:
                 sys.stdout.write('%s: 0  (variable initialized to undefined value) \n' % (name))
                 
    eval_time = time.process_time() 
    #print(f'Eval  time in ms: {(eval_time-ty_time)*1000}\n')

    if ms_infer_required:
            # ms inference
     try:
        qlist = backend.get_modulus_chain()
        tnew = ms_infer(ast[1], gamma, gamma, qlist)

        # Print transformed program
        sys.stdout.write('\n')
        sys.stdout.write('========================================\n')
        sys.stdout.write('Transformed program after MS inference :\n')
        sys.stdout.write('=========================================\n')
        sys.stdout.write('%s\n' % tnew)

        # evaluate new term
        envnew = {}
        tnew.eval(envnew)
        sys.stdout.write('\n')
        sys.stdout.write('==================================\n')
        sys.stdout.write('Eval program after MS inference :\n')
        sys.stdout.write('==================================\n')
        for name in envnew:
            val, noise =  decrypt_or_decode(envnew[name])
            sys.stdout.write('%s: %s (remaining noise budget: %s)\n' % (name, val, noise))
     except Exception as e2:
        sys.stdout.write('MS inference failed\n.', e2)

        #print_error_codes()

