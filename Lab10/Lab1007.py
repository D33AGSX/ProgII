from abc import ABC, abstractmethod
import math

# Clase abstracta principal
class FuncionMatematica(ABC):
    @abstractmethod
    def evaluar(self, x):
        pass

# Clase derivada: Función Lineal (f(x) = m*x + b)
class FuncionLineal(FuncionMatematica):
    def __init__(self, m, b):
        self.m = m
        self.b = b

    def evaluar(self, x):
        return (self.m * x) + self.b

# Clase derivada: Función Cuadrática (f(x) = a*x^2 + b*x + c)
class FuncionCuadratica(FuncionMatematica):
    def __init__(self, a, b, c):
        self.a = a
        self.b = b
        self.c = c

    def evaluar(self, x):
        return (self.a * (x * x)) + (self.b * x) + self.c

# Clase derivada: Función Exponencial (f(x) = a * e^(b*x))
class FuncionExponencial(FuncionMatematica):
    def __init__(self, a, b):
        self.a = a
        self.b = b

    def evaluar(self, x):
        return self.a * math.exp(self.b * x)


# --- Demostración de Polimorfismo ---

# Creamos la lista con las diferentes funciones configuradas con sus valores (m, b, a, c, etc.)
lista_funciones = [
    FuncionLineal(2, 3),          # f(x) = 2x + 3
    FuncionCuadratica(1, -2, 5),  # f(x) = 1x^2 - 2x + 5
    FuncionExponencial(2, 0.5)    # f(x) = 2 * e^(0.5x)
]

# El valor de x en el que se van a evaluar todas las funciones
valor_x = 4

print("Evaluando las funciones en x =", valor_x)
print("-" * 35)

# Recorremos la lista usando polimorfismo
for f in lista_funciones:
    resultado = f.evaluar(valor_x)
    print("El resultado de la función es:", resultado)