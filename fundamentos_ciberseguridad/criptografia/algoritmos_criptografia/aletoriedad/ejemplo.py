# Estoy creando un script único para entender Generación de Aleatoriedad en Criptografía desde cero en primera persona
# Declaro que usaré Python estándar (random, secrets, os) y mostraré ejemplos seguros e inseguros con comentarios en primera persona
# Mi objetivo es: definir conceptos, explicar para qué sirven y demostrar buenas prácticas con código ejecutable

import os  # Importo os porque necesito acceder a fuentes del sistema como os.urandom() para bytes seguros
import random  # Importo random para mostrar un PRNG común (Mersenne Twister) que no debo usar en criptografía
import secrets  # Importo secrets porque provee CSPRNG adecuado para criptografía
import hashlib  # Importo hashlib para construir un ejemplo estilo DRBG basado en hash y explicar derivación
from typing import Tuple  # Importo typing para anotar tipos y hacer el código más claro para mí

# =========================
# 1) CONCEPTOS CLAVE
# =========================

# Defino en mis propias palabras qué es aleatoriedad en criptografía: impredecibilidad práctica de bits/valores
ALEATORIEDAD_DEF = (
    "Aleatoriedad en criptografía es generar valores impredecibles para claves, IVs, salts y tokens."
)  # Escribo una definición breve que yo mismo puedo leer rápidamente

# Enumero para qué sirve la aleatoriedad dentro de mi guion para recordarlo cuando ejecute el script
PARA_QUE_SIRVE = [
    "Claves de cifrado (AES, RSA, ECC) que no se puedan adivinar.",
    "Salts de contraseñas para romper tablas rainbow.",
    "Vectores de inicialización (IV) únicos y/o aleatorios según el modo.",
    "Tokens de sesión/CSRF/OAuth/JWT con alta entropía.",
    "Nonces y retos en protocolos (TLS/SSL, firmas, handshakes).",
]  # Guardo una lista con objetivos prácticos

# Clasifico los tipos de generadores que voy a mostrar: PRNG, CSPRNG, TRNG (conceptual)
TIPOS = {
    "PRNG": "Generador pseudoaleatorio determinista; rápido pero predecible si conozco la semilla.",
    "CSPRNG": "PRNG resistente; impredecible incluso con observación parcial (uso secrets/os.urandom).",
    "TRNG": "Aleatoriedad física real (ruido/Hardware); fuera de alcance de Python puro pero lo explico.",
}  # Declaro el mapa mental mínimo en código

# =========================
# 2) PRNGs (NO SEGUROS)
# =========================

# Implemento un LCG simple para ilustrar un PRNG clásico (NO usar en crypto)
class LCG:  # Creo una clase LCG para demostrar cómo un PRNG determinista depende totalmente de la semilla
    def __init__(self, seed: int, a: int = 1664525, c: int = 1013904223, m: int = 2**32):  # Inicializo con parámetros típicos
        self.state = seed % m  # Guardo el estado inicial modular para simular la evolución del generador
        self.a = a  # Guardo el multiplicador del LCG
        self.c = c  # Guardo el incremento del LCG
        self.m = m  # Guardo el módulo (2^32) para envolver valores

    def next(self) -> int:  # Defino next para producir el siguiente número pseudoaleatorio
        self.state = (self.a * self.state + self.c) % self.m  # Actualizo el estado según la fórmula congruencial
        return self.state  # Devuelvo el número generado (pseudoaleatorio, no apto para seguridad)

    def randint(self, lo: int, hi: int) -> int:  # Agrego un atajo para generar enteros en un rango
        return lo + self.next() % (hi - lo + 1)  # Mapeo el valor al rango inclusivo y retorno el resultado


# Muestro por qué random (Mersenne Twister) no es para criptografía con un ejemplo simple
def demo_prng_inseguro() -> None:  # Creo una función de demostración para aislar el ejemplo
    print("\n[PRNG INSEGURO] random y LCG (solo para simulaciones, NO para criptografía)")  # Anuncio que esto es inseguro
    random.seed(12345)  # Fijo la semilla para que yo mismo vea que la secuencia es repetible
    valores_random = [random.randint(0, 100) for _ in range(5)]  # Genero cinco valores con random (predictibles si conocen la semilla)
    print("random (semilla fija=12345):", valores_random)  # Muestro que la salida es determinista y por tanto predecible

    lcg = LCG(seed=12345)  # Creo un LCG con semilla fija para evidenciar determinismo
    valores_lcg = [lcg.randint(0, 100) for _ in range(5)]  # Genero cinco valores con LCG
    print("LCG (semilla fija=12345):   ", valores_lcg)  # Muestro que también es determinista y no criptoseguro


# =========================
# 3) CSPRNGs (SEGUROS)
# =========================

# Demuestro el uso correcto de secrets y os.urandom para generar bytes y tokens seguros
def demo_csprng() -> None:  # Creo una función para agrupar ejemplos seguros
    print("\n[CSPRNG SEGURO] secrets y os.urandom() para criptografía")  # Anuncio que estos métodos son apropiados
    n = secrets.randbelow(10**6)  # Genero un entero seguro inferior a un millón para demostrar selección uniforme segura
    print("Entero seguro con secrets.randbelow(10**6):", n)  # Imprimo el entero seguro generado

    token_hex = secrets.token_hex(16)  # Genero 16 bytes seguros y los represento en hexadecimal (32 hex chars)
    print("Token seguro (hex, 16 bytes):", token_hex)  # Muestro el token hex que puedo usar como identificador o secreto

    token_url = secrets.token_urlsafe(16)  # Genero un token seguro apto para URLs
    print("Token seguro URL-safe (16 bytes):", token_url)  # Presento el token amigable con URLs

    key_bytes = os.urandom(32)  # Obtengo 32 bytes de alta entropía del sistema (ideal para claves simétricas)
    print("Clave simétrica (32B) con os.urandom:", key_bytes.hex())  # Muestro la clave en hex para visualizarla

    iv = os.urandom(16)  # Creo un IV de 16 bytes como ejemplo típico para AES
    print("IV aleatorio (16B):", iv.hex())  # Enseño el IV y recuerdo que algunos modos requieren unicidad además de aleatoriedad

    salt = os.urandom(16)  # Genero un salt para derivar contraseñas con PBKDF2/Argon2/scrypt (simbolizo con 16 bytes)
    print("Salt para contraseñas (16B):", salt.hex())  # Muestro el salt en hexadecimal para inspección


# =========================
# 4) DRBG sencillo basado en HASH (DEMO EDUCATIVA)
# =========================

# Implemento un mini-DRBG basado en hash para demostrar cómo extender entropía (solo con fines educativos)
class HashDRBG:  # Creo una clase simple para derivar secuencias impredecibles si la semilla inicial es segura
    def __init__(self, seed: bytes):  # Inicio con una semilla de alta entropía (debo usar os.urandom o secrets)
        self.K = hashlib.sha256(seed).digest()  # Derivo un valor interno con SHA-256 para iniciar el estado
        self.V = hashlib.sha256(self.K + b"\x01").digest()  # Creo un vector interno inspirado en diseños DRBG para avanzar

    def _update(self, provided_data: bytes = b"") -> None:  # Defino una rutina interna para refrescar estado
        self.K = hashlib.sha256(self.K + self.V + provided_data).digest()  # Actualizo K con hash del estado y datos opcionales
        self.V = hashlib.sha256(self.K + self.V).digest()  # Refresco V para cambiar el próximo bloque de salida

    def generate(self, nbytes: int) -> bytes:  # Expongo un método para generar n bytes de salida pseudoaleatoria
        out = b""  # Inicializo un buffer vacío para acumular bytes
        while len(out) < nbytes:  # Itero hasta producir la cantidad pedida
            self.V = hashlib.sha256(self.V).digest()  # Avanzo V mediante hash para crear un bloque fresco
            out += self.V  # Acumulo el bloque generado en la salida
        self._update()  # Hago una actualización de estado para forward security básica
        return out[:nbytes]  # Devuelvo exactamente n bytes de salida

    def reseed(self, entropy: bytes) -> None:  # Agrego la capacidad de reseed para mezclar nueva entropía
        self._update(entropy)  # Mezclo entropía adicional en el estado interno como práctica defensiva


def demo_hash_drbg() -> None:  # Creo una demo para usar el HashDRBG
    print("\n[DRBG EDUCATIVO] HashDRBG (solo demo, prefiero usar secrets en producción)")  # Aclaro que es educativo
    seed = os.urandom(32)  # Obtengo una semilla fuerte de 32 bytes desde el sistema
    drbg = HashDRBG(seed)  # Instancio el DRBG con semilla segura
    data1 = drbg.generate(16)  # Genero 16 bytes pseudoaleatorios a partir del estado
    print("Bloque 1 (16B):", data1.hex())  # Muestro el primer bloque en hex
    drbg.reseed(os.urandom(16))  # Reseedeo con entropía fresca para robustez
    data2 = drbg.generate(16)  # Genero un segundo bloque tras reseed
    print("Bloque 2 (16B) tras reseed:", data2.hex())  # Muestro el segundo bloque para comparar

# =========================
# 5) PATRONES PRÁCTICOS SEGUROS
# =========================

# Muestro cómo generaría materiales criptográficos comunes de forma segura
def generar_materiales_seguro() -> Tuple[str, str, str]:  # Especifico que retorno tres cadenas hex para inspección
    clave_aes_256 = os.urandom(32)  # Genero una clave de 256 bits para AES-GCM/CTR/CBC (dependiendo del modo)
    iv_12b_gcm = os.urandom(12)  # Genero un nonce/IV de 96 bits recomendado usualmente en GCM
    salt_pwd = os.urandom(16)  # Genero un salt estándar para KDFs de contraseñas (p.ej., Argon2, PBKDF2, scrypt)
    return clave_aes_256.hex(), iv_12b_gcm.hex(), salt_pwd.hex()  # Devuelvo valores en hex para imprimir fácilmente


# Ilustro claramente qué NO debo hacer al crear secretos (usando random en lugar de secrets)
def anti_patrones_inseguros() -> None:  # Creo una función para evidenciar malas prácticas que debo evitar
    print("\n[ANTI-PATRONES] Esto NO debo hacerlo en criptografía")  # Introduzco la sección de anti-patrones
    random.seed()  # Inicializo random con la semilla por defecto (aún así no es apropiado para crypto)
    pwd_insegura = "".join(str(random.randint(0, 9)) for _ in range(10))  # Construyo una contraseña solo con random
    print("Contraseña INSEGURA con random:", pwd_insegura)  # Muestro que es un ejemplo de lo que no debo hacer

    # Explico por qué está mal: el estado de random puede inferirse y la entropía efectiva suele ser insuficiente
    print("Motivo: 'random' usa Mersenne Twister (determinista) y es predecible; usar 'secrets' en su lugar")  # Dejo mi advertencia en voz propia


# =========================
# 6) TRNG (CONCEPTO Y REALIDAD)
# =========================

# Explico TRNG: normalmente necesito hardware (TPM, HSM, CPU RNG) y el SO ya mezcla esta entropía en su pool
def demo_trng_concepto() -> None:  # Creo una función que explique cómo se expone la aleatoriedad real a usuario
    print("\n[TRNG CONCEPTO] Aleatoriedad por hardware (ruido, jitter, RDRAND), expuesta como os.urandom() por el SO")  # Declaro el panorama
    # Aclaro que en Python yo no llamo directamente al TRNG: el sistema operativo ya mezcla fuentes físicas
    print("En la práctica, yo obtengo bytes desde el pool del SO (os.urandom), que ya integró entropía física y eventos")  # Recalco el flujo realista


# =========================
# 7) EJECUCIÓN GUIADA
# =========================

# Imprimo la introducción y los conceptos para guiarme en consola
print("=== ALEATORIEDAD EN CRIPTOGRAFÍA (GUÍA RÁPIDA) ===")  # Presento un título amigable para mí
print("Definición:", ALEATORIEDAD_DEF)  # Muestro la definición que fijé
print("¿Para qué sirve?")  # Anuncio la lista de propósitos
for item in PARA_QUE_SIRVE:  # Itero para listar cada uso práctico
    print(" -", item)  # Imprimo cada elemento con guion para legibilidad

print("\nTipos de generadores:")  # Introduzco el bloque de clasificación
for k, v in TIPOS.items():  # Recorro el diccionario de tipos
    print(f" * {k}: {v}")  # Imprimo el tipo y su descripción en una línea

# Llamo a las demos en orden lógico para aprender paso a paso
demo_prng_inseguro()  # Ejecuto la demo insegura para fijar por qué no debo usar random/LCG en crypto
demo_csprng()  # Muestro cómo generar enteros, tokens, IVs y salts con fuentes seguras del sistema
demo_hash_drbg()  # Presento un DRBG educativo para comprender extendido de entropía (sin reemplazar secrets)
anti_patrones_inseguros()  # Recalco anti-patrones para no caer en prácticas débiles
demo_trng_concepto()  # Dejo claro el rol del hardware y el SO en la aleatoriedad real

# Genero materiales criptográficos listos para usar como ejemplo final
clave_hex, iv_hex, salt_hex = generar_materiales_seguro()  # Invoco la función que empaqueta buenas prácticas
print("\n[RESUMEN PRÁCTICO] Materiales generados de forma segura:")  # Anuncio un resumen práctico para mí
print("Clave AES-256 (32B):", clave_hex)  # Muestro una clave lista en hexadecimal (no la reutilizaré en producción)
print("IV 96bits para GCM:", iv_hex)  # Muestro un IV/nonce recomendado para GCM
print("Salt (16B) para KDF:", salt_hex)  # Muestro un salt de ejemplo para derivar claves desde contraseñas

# Cierro con recordatorios operativos que quiero mantener presentes
print("\n[RECORDATORIOS]")  # Inicio mis notas finales
print("- Para criptografía: usar 'secrets' y 'os.urandom', nunca 'random'.")  # Refuerzo la regla principal
print("- No reutilizar IV/nonce donde se requiera unicidad (p.ej., GCM debe ser único por clave).")  # Subrayo el riesgo de reutilizar nonces
print("- Almacenar salts junto al hash de contraseña; NO guardo la contraseña ni la clave derivada en texto claro.")  # Anoto la práctica correcta
print("- Considerar KDFs modernos (Argon2, scrypt, PBKDF2) y gestores de claves seguros/HSM si es posible.")  # Dejo recomendaciones de siguiente nivel
print("- Si necesito certificaciones/estándares, revisar NIST SP 800-90A/B/C para DRBGs y guías de RNG.")  # Apunto a normativas reconocidas

