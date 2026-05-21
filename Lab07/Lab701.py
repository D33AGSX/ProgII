# Calculadora Factorial

print ("Lab701: Calculadora Factorial")

while True:
    try:
        print ("Ingrese un número entero positivo:")
        n = int (input("=> "))
        if n >= 0:
            break
        else:
            print (" *El número ingresado no es mayor o igual a 0*")
    except ValueError:
        print ("Debe ser un número entero.")
f = 1
i = 1

while i <= n:
    f *= i
    i += 1

print (f"El factorial de {n} es: {f}")