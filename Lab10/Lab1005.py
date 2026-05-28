n = int(input("Introduce un número: "))
f = 1

for i in range(n):
    f = f * (i + 1)

print("El factorial es:", f)