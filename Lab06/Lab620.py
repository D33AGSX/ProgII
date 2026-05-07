# Definicion manual
matriz = [
    [1, 2, 3],
    [4, 5, 6],
    [7, 8, 9]
]

# Generacion automatica (Matriz identidad 3x3)
n = 3
identidad = [[1 if i == j else 0 for j in range(n)] for i in range(n)]


for fila in matriz:
    for elemento in fila:
        print (elemento, end="\t")
    print () #Salto de linea al termiar la fila