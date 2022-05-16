import os.path
import socket
from nacl.signing import SigningKey
from nacl.encoding import Base64Encoder

Tamanio = 1024
Formato = "utf-8"


def enviar_d(direccion, nom_archivo):
    archivo = open(direccion)
    datos = archivo.read()

    cliente.send(nom_archivo.encode(Formato))
    msj = cliente.recv(Tamanio).decode(Formato)
    print(f"[Server]: {msj}")

    cliente.send(datos.encode(Formato))
    msj_alt = cliente.recv(Tamanio).decode(Formato)
    print(f"[Server]: {msj_alt}")

    archivo.close()
    return 0


def firma(direccion):
    with open(direccion, "rb") as archivo:
        contenido = archivo.read(Tamanio)
        llave_fir = SigningKey.generate()
        firma_d = llave_fir.sign(contenido, encoder=Base64Encoder)
        llave_ver = llave_fir.verify_key
        llave_ver_x = llave_ver.encode(encoder=Base64Encoder)
        cliente.send(opc)
        cliente.send(llave_ver_x)
        cliente.send(firma_d.signature)
        # cliente.send(contenido)
    return 0


print("Seleccione:\n[1]Cifrado\t[2]Descifrado\n[3]Firma\t[4]Vefiricación de firma\n[0]Salir")
opc = int(input("\n?"))
dir_archivo = input("Dirección de memoria del archivo: ")
nom = open(dir_archivo, "r+")
n_archivo = os.path.basename(nom.name)

cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
cliente.connect((socket.gethostname(), 4456))
while True:
    if opc == 1:
        cliente.send(str(opc).encode(Formato))
        enviar_d(dir_archivo, n_archivo)
    if opc == 2:
        cliente.send(bytes(opc))
        enviar_d(dir_archivo, n_archivo)
    if opc == 3:
        cliente.send(bytes(opc))
        enviar_d(dir_archivo, n_archivo)
    if opc == 4:
        cliente.send(bytes(opc))
        firma(dir_archivo)
    if (opc < 0) or (opc > 4):
        print("Seleccione una opción valida:\n[1]Cifrado\t[2]Descifrado\n[3]Firma\t[4]Vefiricación de firma\n[0]Salir")
        opc = input(int("\n?"))
    if opc == 0:
        break
    else:
        break
