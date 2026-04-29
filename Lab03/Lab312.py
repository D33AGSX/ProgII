#1. Literal de bytes (forma mas comun)
mi_byte = b"\xFF"

#2. Constructor bytes a partir de un entero
mi_byte_dos = bytes ([255])

#Verificacion
print (type(mi_byte)) # <class 'bytes'>
print (mi_byte[0]) # 255