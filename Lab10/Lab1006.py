from abc import ABC, abstractmethod
import math

# Definición de la clase abstracta
class Figura(ABC):
    @abstractmethod
    def calcularArea(self):
        pass

# Clase derivada: Círculo
class Circulo(Figura):
    def __init__(self, radio):
        self.radio = radio

    def calcularArea(self):
        return math.pi * (self.radio * self.radio)

# Clase derivada: Rectángulo
class Rectangulo(Figura):
    def __init__(self, base, altura):
        self.base = base
        self.altura = altura

    def calcularArea(self):
        return self.base * self.altura

# Clase derivada: Triángulo
class Triangulo(Figura):
    def __init__(self, base, altura):
        self.base = base
        self.altura = altura

    def calcularArea(self):
        return (self.base * self.altura) / 2


# --- Demostración de Polimorfismo ---

# Creación de una lista con diferentes tipos de figuras
lista_figuras = [
    Circulo(5),
    Rectangulo(4, 6),
    Triangulo(3, 8)
]

# Recorrer la lista mostrando el área de cada figura de forma dinámica
for f in lista_figuras:
    print("El área de la figura es:", f.calcularArea())