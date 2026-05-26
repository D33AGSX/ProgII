class Persona:
    # Atributo estático (compartido por todas las instancias)
    contador = 0

    def __init__(self):
        Persona.contador += 1 # Se accede con el nombre de la clase