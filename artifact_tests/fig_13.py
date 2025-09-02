from ila import *

def bgv_openfhe():
    depth = {}
    for i in range (2, 20):
        # flag = True
        ila_depth = 0
        for j in range (i-1, 25):
            with open("fig_13.ila", "w") as f:
                f.write("x : cipher;\ny : cipher\n\nx := cinit(10);\ny := cinit(1);\nwhile "+str(j)+"\ndo\n      x := x & y\nend\n")
            f.close
            (typecheck, outputs, logq) = ila (2, 2, "fig_13.ila", i)
            if typecheck[0] == False:
                ila_depth = j - 1
            if outputs['x'][0] != 10:
               depth[logq] = (ila_depth, j-1)
               break
    print("********** ILA BFV vs OpenFHE multiplicative depth **********")
    print("q in bits \t\t ILA_BFV \t Max possible")
    for keys in depth:
        print(keys, depth[keys])
    exit(0)

if __name__ == '__main__':
    bgv_openfhe()
