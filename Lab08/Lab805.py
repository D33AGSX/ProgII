class Persona:
    def __init__(self, nom, ed):
        self.nombre = nom
        self.edad = ed

    def celebrar_cumple(self):
        self.edad += 1

p1 = Persona("Fulano", 28)
p1.celebrar_cumple()
print(p1.edad)