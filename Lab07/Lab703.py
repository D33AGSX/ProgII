import string

print("Lab703: Herramienta para métricas de texto")

texto = input("Ingrese una cadena de texto larga:\n=> ")

#Palabras Unicas
texto_limpio = texto.lower()
for car in string.punctuation:
    texto_limpio = texto_limpio.replace(car, "")

palabras = texto_limpio.split()
lista_unicas = []
for p in palabras:
    if p not in lista_unicas:
        lista_unicas.append(p)
total_unicas = len(lista_unicas)

#Palabra mas larga
if len(palabras) > 0:
    ganador = palabras[0]
    for p in palabras:
        if len(p) > len(ganador):
            ganador = p
else:
    ganador = "N/A"

#Frecuencia de Caracteres
solo_letras = texto.replace(" ", "")
total_caracteres = len(solo_letras)
frecuencia = {}

for letra in solo_letras:
    if letra in frecuencia:
        frecuencia[letra] = frecuencia[letra] + 1
    else:
        frecuencia[letra] = 1

#Reporte Final
print("REPORTE DE MÉTRICAS")
print(f"Palabras únicas: {total_unicas}")
print(f"Palabra más larga: {ganador}")

print("\nFrecuencia de Caracteres:")
for letra in frecuencia:
    cantidad = frecuencia[letra]
    porcentaje = (cantidad / total_caracteres) * 100
    print(f"'{letra}': {cantidad} veces ({porcentaje:.2f}%)")