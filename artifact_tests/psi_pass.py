# This test return 0 if both client data and server data are same.
# Return a random value otherwise.
# This test passes as both client data and server data = [1 0 2 -2]
from ila import *

def psi_pass():

    with open("psi_pass.ila", "w") as f:
        f.write('client_data : vec cipher 4;\nserver_data : vec cipher 4;\nrandom_plain_data : vec plain 4;\nresult : cipher;\nn_unit : plain;\ni : int;\nj : int;\nt1 : plain;\nt2: cipher;\nt3: cipher;\nt4 : plain;\nt5 : cipher;\nt6 : cipher\n\n\n\nclient_data := vinit[1 0 2 -2];\nserver_data := vinit[1 0 2 -2];\nrandom_plain_data := vinit[-1 2 -1 1];\nresult := cinit(1);\nn_unit := pinit(-1);\nj :=1;\n i :=1;\n \nwhile j\ndo\n t1 := index(server_data,j);\n t2 := n_unit & t1;\n t3 := index(random_plain_data, j);\n t4 := result & t3;\n\n\nwhile i\ndo\n  t5 := index(client_data, i);\n  t6 := t5 @ t2;\n  t7 := result & t6;\n  result := t7 & t4\n end;\n\n i :=1\n\n end\n\n\n')
    f.close
    (typecheck, outputs, logq) = ila (1, 1, "psi_pass.ila", 20)
    print("********** Private Set Intersection **********")
    print(outputs['result'])

if __name__ == '__main__':
    psi_pass()
