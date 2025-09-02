from ila import *

def bgv_openfhe():
    depth = {}
    for i in range (1, 18):
        ila_depth = 0
        for j in range (i, 30):
            with open("fig_14.ila", "w") as f:
                f.write("x : cipher;\ny : plain\n\nx := cinit(10);\ny := pinit(1);\nwhile "+str(j)+"\ndo\n      x := x & y\nend\n")
            f.close
            (typecheck, outputs, logq) = ila (2, 1, "fig_14.ila", i)
            if typecheck[0] == False:
                ila_depth = j - 1
            if outputs['x'][0] != 10:
               print(i, ila_depth, j-1)
               depth[logq] = (i, ila_depth, j-1)
               break
    print("********** ILA BGV vs OpenFHE multiplicative depth **********")
    print("q in bits \t Open FHE \t ILA_BGV \t Max possible")
    for keys in depth:
        print(keys, depth[keys])
    exit(0)

if __name__ == '__main__':
    bgv_openfhe()
