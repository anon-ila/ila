from numpy import longdouble
from ila import *

def tfhe():
    total_time = longdouble(0)
    times = {}
    for depth in range (3,18):
        for i in range (0, 1000):
            with open("tfhe.ila", "w") as f:
                #f.write('x1 : cipher <0,1>;\nx2 : cipher <1,3>;\nz : cipher\n x1 := cinit(1);\nx2 := cinit(3);\nwhile 450\ndo\n  z := x1 @ x2\nend')
                f.write('x1 : cipher <0,2>;\nx2 : cipher <0,4> \n\nx1 := cinit(1);\nx2 := cinit(3);\nwhile 4500\ndo\n  x2 := x1 @ x2\nend')
            f.close
            (chk_time, err) = ila (3, 3, "tfhe.ila", depth)
            # print("check_time is",chk_time, err)
            if err[0] == True:
                total_time += longdouble(chk_time)
        times[err[1]] = total_time
        total_time = 0
    print("********** ILA TFHE Value Overflow Times **********")
    print("# of computations \t ILA run time in milli seconds")
    for keys in times:
        print("\t\t", keys, "\t\t", times[keys])

if __name__ == '__main__':
    tfhe()
