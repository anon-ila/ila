
# Online Python - IDE, Editor, Compiler, Interpreter

client_data = [2, -2, 3]
server_data = [-1, 0, 2]
random_plain_data = [1,-2,-3]
result = 1
n_unit = -1

j = 2

while j >= 0:
    t1 =  server_data[j]
    t2 = n_unit * t1
    t3 = random_plain_data[j]
    t4 = result * t3
    i = 2
    while i >= 0:
        t5 = client_data[i]
        t6 = t5 + t2
        t7 = result * t6
        result = t7 * t4 
        i -= 1
    j -= 1
print(result)
    
