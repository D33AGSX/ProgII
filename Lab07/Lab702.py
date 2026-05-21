print("Generador de Matriz Identidad (Orden Par)")

while True:
    try:
        print ("Ingrese el tamaño de la matriz, el numero debe ser par")
        n = int(input("=> "))
        if n > 0 and n % 2 == 0: 
            break
        else:
            print("Error: El número debe ser positivo y par.")
    except ValueError:
        print("Entrada inválida. Ingrese un número entero.")

matriz = [[1 if i == j else 0 for j in range(n)] for i in range(n)]

for fila in matriz: #navega entre las listas
    for elemento in fila: #imprime el valor dentro de la lista
        print(elemento, end="\t") # \t tabula en vez de agregar un salto de pagina.
    print() #Salto de linea