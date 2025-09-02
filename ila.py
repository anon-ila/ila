#!/usr/bin/env python


import sys
import time
from ila_parser import *
from ila_lexer import *
# import gc
import subprocess

class Tree():
    def __init__(self, root):
        self.root_val = root
        self.left = None
        self.right = None
        self.children = []


def usage():
    sys.stderr.write('Usage: ila <backend> <scheme_type> <filename> <optional scheme params> \n')
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
        return (backend.vector_decrypt(fv.v))
    elif fv.tag == 4:
        return (backend.vector_decode(fv.v))
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

# Find parent, finds the parent of a node with the largest depth 
    # in the tree with the root node where ILA typecheck failed due to noise overflow.
            
def find_parent(tree, parent, depth, traversed):
    if tree.left == tree.right == None or tree in traversed:
        return(parent, depth)
    else:
        traversed.append(tree)
        if tree.left != None and tree.right != None:
            node_l, depth_l = find_parent(tree.left, tree.root_val, depth+1, traversed)
            node_r, depth_r = find_parent(tree.right, tree.root_val, depth+1, traversed)
            if depth_l > depth_r:
                return (node_l, depth_l)
            else:
                return(node_r, depth_r)
        elif tree.left == None:
            return (find_parent(tree.right, tree.root_val, depth+1, traversed))
        else:
            return(find_parent(tree.left, tree.root_val, depth+1, traversed))

# Constructs the chain with stmt as the end node
def MulDepthTree(def_list, stmt, backend):
    name = stmt.name
    schme_type = 2
    if name not in def_list:
        # if the variable is not defined forexample x := cinit(1) 
        return None
    else:
        root = Tree(stmt)
        exp = stmt.exp
        left = exp.left
        right = exp.right
        if left.name in def_list:
            # if x := x \otimes y, no need to traverse further
            if left.name != def_list[left.name][0].left.name and left.name != def_list[left.name][0].right.name:
                if not isinstance(left.name, UnaryopPexp):
                # else already mod switched
                # a variable is not defined if forexample is an external constant
                # or x := ms(x2) \otimes (x3)
                # ms(x) 
                    left_stmt = AssignStatement(left.name, def_list[left.name][0], schme_type, backend, def_list[left.name][1]) 
                    root.left = MulDepthTree(def_list, left_stmt, backend)
        if right.name in def_list:
            if right.name != def_list[left.name][0].left.name and left.name != def_list[left.name][0].right.name:
                if not isinstance(right.name, UnaryopPexp): 
                    right_stmt = AssignStatement(right.name, def_list[right.name][0], schme_type, backend, def_list[right.name][1]) 
                    root.right = MulDepthTree(def_list, right_stmt, backend)
        return root
    

def get_children_exp(expr, names):
    if isinstance(expr, VarPexp):
        return(names.append(expr.name))
    if isinstance(expr, BinopPexp):
        names_l = get_children_exp(expr.left, names)
        names_r =  get_children_exp(expr.right, names)
        return(list(set(names_l).union(names_r)))
    return(names)

def get_msnodes_comp(def_list, stmt, backend):
    name = stmt.name
    schme_type = 2
    if name not in def_list:
        # if the variable is not defined forexample x := cinit(1) 
        return None
    else:
        if isinstance(exp, BinopPexp):
            if exp.op != "&": 
                return None
        root = Tree(stmt)
        children = get_children_exp(stmt.exp, [])
        exp = stmt.exp
        left = exp.left
        right = exp.right
        if left.name in def_list:
            # if x := x \otimes y, no need to traverse further
            if left.name != def_list[left.name][0].left.name and left.name != def_list[left.name][0].right.name:
                if not isinstance(left.name, UnaryopPexp):
                # else already mod switched
                # a variable is not defined if forexample is an external constant
                # or x := ms(x2) \otimes (x3)
                # ms(x) 
                    left_stmt = AssignStatement(left.name, def_list[left.name][0], schme_type, backend, def_list[left.name][1]) 
                    root.left = MulDepthTree(def_list, left_stmt, backend)
        if right.name in def_list:
            if right.name != def_list[left.name][0].left.name and left.name != def_list[left.name][0].right.name:
                if not isinstance(right.name, UnaryopPexp): 
                    right_stmt = AssignStatement(right.name, def_list[right.name][0], schme_type, backend, def_list[right.name][1]) 
                    root.right = MulDepthTree(def_list, right_stmt, backend)
        return root
    
def get_level(t):
    split_list = t.rsplit(" ", 1)
    left = split_list[0]
    om = int(split_list[1][:-1])
    return left,om 
 
def get_level_exp(exp):
    if isinstance(exp, VarPexp):
        _, om = get_level(gamma[exp.name])
        exp.level = om
        return(om)
    return(exp.level)


def get_ms_assign (node, level):
    left = UnaryopPexp('ms', node.exp.left, backend, 1, node.id)
    right = UnaryopPexp('ms', node.exp.right, backend, 1, node.id)
    exp = BinopPexp( '&', left, right, backend,1)
    exp.level = left.level = right.level = level-1
    return(AssignStatement(node.name, exp, 1, backend, node.id))

def get_ms_assign_left (node, level):
    left = UnaryopPexp('ms', node.exp.left, backend, 1, node.id)
    exp = BinopPexp( '&', left, node.exp.right, backend,1)
    exp.level = left.level  = level
    return(AssignStatement(node.name, exp, 1, backend, node.id))

def get_ms_assign_right (node, level):
    right = UnaryopPexp('ms', node.exp.right, backend, 1, node.id)
    exp = BinopPexp( '&', node.exp.left, right, backend,1)
    exp.level = right.level = level
    return(AssignStatement(node.name, exp, 1, backend, node.id))

def new_ast(parent, old_ast, gamma): 
    if old_ast.second == None:
        return (old_ast, gamma)
    second = old_ast.second
    a, om = get_level(gamma[second.name])
    if parent.id == second.id:
        gamma[second.name] = a+ " " + str(om-1) + ">"
        old_ast.second = get_ms_assign(parent, om)
        return (old_ast, gamma)
    else:
        (first, gamma) = new_ast (parent, old_ast.first, gamma)
        l, left_level = get_level(gamma[second.exp.left.name])
        r, right_level = get_level(gamma[second.exp.right.name])
        if  left_level == right_level:
            gamma[second.name] =  a+ " " + str(left_level) + ">"
            return( CompoundStatement(first, second), gamma)
        elif right_level < left_level:
            gamma[second.name] =  a+ " " + str(right_level) + ">"
            return (CompoundStatement(first, get_ms_assign_left(second, right_level)), gamma)
        else:
            gamma[second.name] =  a+ " " + str(left_level) + ">"
            return (CompoundStatement(first, get_ms_assign_right(second, left_level)), gamma)


def ila (back, scheme_ty, filename, mul_depth):
    # read input file
    text = open(filename).read()
    tokens = ila_lex(text)
    try:
        parse_result = ila_parse(tokens, back, scheme_ty, mul_depth)
    except TypecheckError as e:
        sys.stdout.write ('%s' %e)
        sys.exit(1)
    global backend
    ast, backend, def_list = parse_result[0].value, parse_result[1], parse_result[2]
    # print(def_list)
    logq, coeff_mod, plain_mod, degree = backend.get_params_default()
    env = {}
    global gamma
    gamma = {}
    ast[0].eval(gamma)
    # ms_infer_required = False
    typecheck_fail = (False, 0)
    outputs = {}
    # sys.stdout.write('Variable types:\n')
    #for name in gamma:
    #    sys.stdout.write('%s: %s\n' % (name, gamma[name]))
    err = ""
    start_time = time.perf_counter()
    while True:
        try:
            # run type checker on the ast
            # sys.stdout.write('\nType infering ...\n')
            error, gamma = ast[1].typeinfer(gamma=gamma, def_list=def_list, logq=logq, q=coeff_mod, t=plain_mod, degree=degree)
            sys.stdout.write('Type infer passed')
            sys.stdout.write('\n*****************************************\n')
            if error != "":
                print(error)
            break
        except MSInferError as e:
            err = e
            if not ms_infer:
                typecheck_fail = (True, e.error_code)
                break
            #e.error_code == 13: # M is 13th letter, 13 refers to MS inference
                # MS inference can typecheck the program
                # traverse ast and find the chain that ends with stmt
            path = MulDepthTree(def_list, e.stmt, e.backend) 
            parent, _ = find_parent(path, None, 0, [])
            if parent == None:
                raise (TypecheckError("Type Inference failed", 240))
            else:
                # parent.exp.left 
                a,om = get_level(gamma[parent.name])
                if om == 0:
                    raise (TypecheckError("Type Inference failed", 319))
                (updated_ast, gamma) = new_ast(parent, ast[1], gamma)
                print(updated_ast)
                try: # remove this
                    error, gamma = updated_ast.typeinfer(gamma=gamma, def_list=def_list, logq=logq, q=coeff_mod, t=plain_mod, degree=degree)
                    sys.stdout.write('Type infer passed')
                    sys.stdout.write('\n*****************************************\n')
                    break
                except MSInferError as e:
                    print(e.stmt)
                    break
        except TypecheckError as e:
            if e.error_code == 177:
                typecheck_fail = (True, -1)
            else:
                typecheck_fail = (True, e.error_code)
            break
        except Exception as e:
            raise e
            

            #sys.stdout.write('==================================\n')
            #sys.stdout.write('%s\n' % e)
            #sys.stdout.write('Returned error code: %s\n' % e.error_code)
            #ys.stdout.write('==================================\n')
            #code = e.error_code
            #if code == 3 or code == 13:
            #    ms_infer_required = True

    #print("Types after inference", gamma)
    end_time = time.perf_counter()
    execution_time = (end_time - start_time)

    print(f"Execution time: " + '{:.10f}'.format(execution_time) + " seconds\n")
    #print("Error is:", typecheck_fail[1])

    if (scheme_ty == 3): #change to '3'
        # compile to TFHE-rs
        #subprocess.run(["rm", "-rf", "output"])
        #subprocess.run(["cargo", "new", "output", "--bin"])
        #f = open("output/Cargo.toml", "a")
        #f.write("\ntfhe = { version = \"*\", features = [\"boolean\", \"shortint\", \"integer\"] }\n")
        #f.close()
        #f = open("output/src/main.rs", "w")
        #compile_prelude(f)
        #s = ast[1].compile()
        #f.write(s)

        # ideally, decrypt all encrypted vars
        # but that requires some way of collecting all vars
        #compile_epilogue(f)
        #close file
        #f.close()
        #eval_time = time.process_time() 
        return (execution_time, typecheck_fail)
    else:
        #print env
        sys.stdout.write('\nEvaluating ILA Program ...\n')
        try:
            ast[1].eval(env)
        except RuntimeError as e:
            raise e
        # sys.stdout.write('Final variable values:\n')
        for name in env:
            p = env[name]
            if isinstance(p, VecValue):
                # iterate through the vector
                if p.tag == 3:
                    val, noise =  decrypt_or_decode(Value(p.v, 3))
                    # sys.stdout.write('%s: %s (remaining noise budget: %s)\n' % (name, val, noise))
                    outputs[name] = val
                elif p.tag == 4:
                    val =  decrypt_or_decode(Value(p.v, 4))
                    outputs[name] = val
                    #sys.stdout.write('%s: %s \n' % (name, val))
                elif p.tag == 5:
                    val, _ =  decrypt_or_decode(p)
                    outputs[name] = val
                else:
                    val =  decrypt_or_decode(p)
                    outputs[name] = val
            elif isinstance(p, Value):
                # Cipher value
                if p.tag == 1 or p.tag == 2:
                    val, noise =  decrypt_or_decode(p)
                    outputs[name] = val
                    #sys.stdout.write('%s: %s (remaining noise budget: %s)\n' % (name, val, noise))
                elif p.tag == 0:
                    # plain int
                    outputs[name] = p.v
                    #sys.stdout.write('%s: %s)\n' % (name, p.v))
            else:
                 sys.stdout.write('%s: 0  (variable initialized to undefined value) \n' % (name))
    eval_time = time.process_time() 
    # print(f'Eval  time in ms: {(eval_time-ty_time)*1000}\n')
    return(typecheck_fail, outputs, logq)


        #print_error_codes()

if __name__ == '__main__':
    # usage: ila.py <backend> <scheme>  <filename>
    if len(sys.argv) != 5:
        if len(sys.argv) != 4 and sys.argv[1] != 3:
            usage()

    backend = int(sys.argv[1])
    scheme_ty = sys.argv[2]
    filename = sys.argv[3]
    mul_depth = 0
    if scheme_ty == 2:
        mul_depth = int(sys.argv[4])
    ila (backend, scheme_ty, filename, mul_depth)
