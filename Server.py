import socket
from nacl.signing import SigningKey
import os
from nacl.signing import VerifyKey
from nacl.encoding import Base64Encoder
import nacl.utils
import nacl.secret
import nacl.pwhash

formato = "utf-8"
tamanio = 1024
IP = socket.gethostbyname(socket.gethostname())
Puerto = 4456
Dir = (IP, Puerto)
local = os.getcwd()
kdf = nacl.pwhash.argon2i.kdf
salt = nacl.utils.random(16)
password = "EntregaCifrada".encode(formato)
llave = kdf(nacl.secret.SecretBox.KEY_SIZE, password, salt)
cont = nacl.secret.SecretBox(llave)


def cifrar(n_archivo):
    archivo_sc = open(n_archivo, "rb")
    datos_sc = archivo_sc.read()
    archivo_sc.close()

    datos_cc = cont.encrypt(datos_sc)

    archivo_cc = open("CC-"+n_archivo, "wb")
    archivo_cc.write(datos_cc)
    archivo_cc.close()


def descifrar(n_archivo):
    archivo_cc = open(n_archivo, "rb")
    datos_cc = archivo_cc.read()
    archivo_cc.close()

    datos_ss = cont.decrypt(datos_cc)

    archivo_ss = open("SC-"+n_archivo, "wb")
    archivo_ss.write(datos_ss)
    archivo_ss.close()


def uno():
    n_archivo = conx.recv(tamanio).decode(formato)
    print(f"[Recibido] {n_archivo} recibido")
    archivo = open(n_archivo, "w")
    conx.send("Nombre de archivo recibido".encode(formato))

    datos = conx.recv(tamanio).decode(formato)
    print(f"[Recibido] Datos recibidos")
    archivo.write(datos)
    conx.send("Datos recibidos".encode(formato))
    archivo.close()

    cifrar(n_archivo)
    conx.close()
    return 0


def dos():
    n_archivo = conx.recv(tamanio).decode(formato)
    print(f"[Recibido] {n_archivo} recibido")
    archivo = open(n_archivo, "w")
    conx.send("Nombre de archivo recibido".encode(formato))

    datos = conx.recv(tamanio).decode(formato)
    print(f"[Recibido] Datos recibidos")
    archivo.write(datos)
    conx.send("Datos recibidos".encode(formato))
    archivo.close()
    descifrar(n_archivo)
    conx.close()
    return 0


def tres():
    n_archivo = conx.recv(tamanio).decode(formato)
    print(f"[Recibido] {n_archivo} recibido")
    archivo = open("DF-"+n_archivo, "wb")
    conx.send("Nombre de archivo recibido".encode(formato))

    datos = conx.recv(tamanio).decode(formato)
    print(f"[Recibido] Datos recibidos")
    conx.send("Datos de archivo recibido".encode(formato))

    llave_firma = SigningKey.generate()
    firma_b64 = llave_firma.sign(bytes(datos), encoder=Base64Encoder)
    llave_ver = llave_firma.verify_key
    llave_ver_b64 = llave_ver.encode(encoder=Base64Encoder)

    archivo.write(bytes(firma_b64))
    conx.send("Datos recibidos".encode(formato))
    archivo.close()
    conx.close()
    return 0


def cuatro():
    llave_ver_x = conx.recv(64)
    firma = conx.recv(tamanio)
    verificar = VerifyKey(llave_ver_x, encoder=Base64Encoder)
    return verificar.verify(firma, encoder=Base64Encoder)


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(Dir)
server.listen()
print("[Escuchando...]")

while True:
    conx, direc = server.accept()
    opc = conx.recv(1)  # opc = conx.recv(1)
    print(f"[Nueva conexion] {dir} conectado: Opcion {opc}")
    if opc == b'1':
        uno()
        conx.close()
    if opc == b'2':
        dos()
    if opc == b'3':
        tres()
    if opc == b'4':
        cuatro()
        conx.close()
