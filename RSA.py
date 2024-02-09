from hashlib import sha256
import PrimeUtils
import base64
import asn1tools

PKCS1_ENCODER = asn1tools.compile_files('specifications/pkcs1.asn', 'ber')
PKCS8_ENCODER = asn1tools.compile_files('specifications/pkcs8.asn', 'der')

class RSA:
    @property
    def __bits(self): # n.bit_length
        return self.n.bit_length()

    @property
    def public_key(self): # tuple: (e, n)
        return (self.e, self.n)

    @property
    def private_key(self): # tuple: (d, n)
        return (self.d, self.n)
    
    @property
    def BLOCK_SIZE(self): # floor(n/8)
        return self.__bits // 8

    def __init__(self):
        pass

    """ KEY GENERATION """
    def generate_keys(self, __bits=2048):  # TODO: Sabrina
        # Generate p and q
        self.p = PrimeUtils.generate_random_nbits(__bits//2)
        self.q = PrimeUtils.generate_random_nbits(__bits//2)

        # Calclate n and phi(n)
        self.n = self.p*self.q
        phi_n = PrimeUtils.phi(self.p, self.q)
    
        # Calculate 'e' and 'd'
        self.e = 65537
        self.d = PrimeUtils.inverse_modulo(self.e, phi_n)

        # Calculate coefficients for quick decryption
        self.dp = self.d % (self.p - 1)
        self.dq = self.d % (self.q - 1)
        self.up = self.q*(PrimeUtils.inverse_modulo(self.q, self.p)) % self.n
        self.uq = self.p*(PrimeUtils.inverse_modulo(self.p, self.q)) % self.n

        return (self.e, self.n), (self.d, self.n)

    """ PADDING """
    def __pad(self, message, BLOCK_SIZE):
        pad_size = (BLOCK_SIZE - (len(message) % BLOCK_SIZE)) % BLOCK_SIZE
        return b"\x00"*pad_size + message;

    def __unpad(self, message):
        return message.lstrip(b'\x00')

    """ ENCODING and DECODING """
    def __split_into_blocs(self, message, BLOCK_SIZE):
        return [message[i:i+BLOCK_SIZE] for i in range(0, len(message), BLOCK_SIZE)]

    def __encode(self, bytes):
        return int.from_bytes(bytes, byteorder="big", signed=False)

    def __decode(self, number, BLOCK_SIZE):
        return number.to_bytes(max(1, BLOCK_SIZE), byteorder="big")

    """ ENCRYPTION """
    def encrypt(self, message): # TODO: Brahim
        ciphertext = []
        message = self.__pad(message, self.BLOCK_SIZE-1)
        blocks = self.__split_into_blocs(message, self.BLOCK_SIZE-1)
        for block in blocks:
            block_int = self.__encode(block)
            c = PrimeUtils.square_n_multiply(block_int, self.e, self.n)
            ciphertext.append(self.__decode(c, self.BLOCK_SIZE))
            #print(block, ":", self.__encode(block), "-->", c)
            
        return b"".join(ciphertext)

    """ DECRYPTION """
    def decrypt(self, ciphertext): # TODO: Brahim
        message = []
        blocks = self.__split_into_blocs(ciphertext, self.BLOCK_SIZE)
        for block in blocks:
            c_int = self.__encode(block)
            xp = PrimeUtils.square_n_multiply(c_int, self.dp, self.p)
            xq = PrimeUtils.square_n_multiply(c_int, self.dq, self.q)
            m = (xp*self.up + xq*self.uq) % self.n
            message.append(self.__decode(m, self.BLOCK_SIZE-1))
            #print(block, ":", self.__encode(block), "-->", m)
        
        message = self.__unpad(b"".join(message))
        return message

    """ LOAD AND SAVE """
    def save_keys(self, publicPath, privatePath):
        self.save_publicKey(publicPath)
        self.save_privateKey(privatePath)
        return

    def save_publicKey(self, filepath): # TODO: Leila
        # ENCODE public key into ASN1, DER (bytes)
        publicKey = {
            "modulus": self.n,
            "publicExponent": self.e
        }
        publicKey_ber = PKCS1_ENCODER.encode("RSAPublicKey", publicKey)

        # bytes -> base64
        publicKey_base64 = base64.b64encode(publicKey_ber).decode('utf-8')
        publicKey_base64 = [publicKey_base64[i:i+64] for i in range(0, len(publicKey_base64), 64)]
        publicKey_base64 = "\n".join(publicKey_base64)

        # Write to filepath
        f = open(filepath,'w')
        f.write('-----BEGIN PUBLIC KEY-----\n')
        f.write(publicKey_base64+'\n')
        f.write('-----END PUBLIC KEY-----')
        f.close()

    def save_privateKey(self, filepath): # TODO: Leila
        # ENCODE private key into ASN1, DER (bytes)
        privateKey = {
            "version": 0,
            "modulus": self.n,
            "publicExponent": self.e,
            "privateExponent": self.d,
            "prime1": self.p,
            "prime2": self.q,
            "exponent1": self.dp,
            "exponent2": self.dq,
            "coefficient": self.uq
        }
        privateKey_ber = PKCS1_ENCODER.encode("RSAPrivateKey", privateKey)
        privateKey = {
            "version": 0,
            "algorithm": {'algorithm': "1.2.840.113549.1.1.1", 'parameters': None},
            "privateKey": privateKey_ber
        }
        privateKey_der = PKCS8_ENCODER.encode("PrivateKeyInfo", privateKey)
        # bytes -> base64
        privateKey_base64 = base64.b64encode(privateKey_der).decode('utf-8')
        privateKey_base64 = [privateKey_base64[i:i+64] for i in range(0, len(privateKey_base64), 64)]
        privateKey_base64 = "\n".join(privateKey_base64)

        # Write to filepath
        f = open(filepath,'w')
        f.write('-----BEGIN PRIVATE KEY-----\n')
        f.write(privateKey_base64+'\n')
        f.write('-----END PRIVATE KEY-----')
        f.close()

    def load_keys(self, publicPath, privatePath):
        self.load_publicKey(publicPath)
        self.load_privateKey(privatePath)
        return

    def load_publicKey(self, filepath): # TODO: Leila
        # Read filepath
        f = open(filepath,'rb')
        publicKey_base64 = b"".join(f.read().splitlines()[1:-1])
        f.close()

        # Base64 -> Bytes (ASN1, (PCKS#8)DER)
        publicKey = base64.b64decode(publicKey_base64)

        # PKCS#1 (ASN) -> Object
        publicKey = PKCS1_ENCODER.decode('RSAPublicKey', publicKey)
        self.n = publicKey['modulus']
        self.e = publicKey['publicExponent']
    
    def load_privateKey(self, filepath): # TODO: Leila
        # Read filepath
        f = open(filepath,'rb')
        privateKey_base64 = b"".join(f.read().splitlines()[1:-1])
        f.close()

        # Base64 -> Bytes ((PKCS#8)ASN1, DER)
        privateKey = base64.b64decode(privateKey_base64)
        privateKey = PKCS8_ENCODER.decode('PrivateKeyInfo', privateKey)['privateKey']

        # ASN1 -> Object
        privateKey = PKCS1_ENCODER.decode('RSAPrivateKey', privateKey)
        self.n = privateKey['modulus']
        self.e = privateKey['publicExponent']
        self.d = privateKey['privateExponent']
        self.p = privateKey['prime1']
        self.q = privateKey['prime2']
        self.dp = privateKey['exponent1']
        self.dq = privateKey['exponent2']
        self.up = self.q*(PrimeUtils.inverse_modulo(self.q, self.p)) % self.n
        self.uq = self.p*(PrimeUtils.inverse_modulo(self.p, self.q)) % self.n

    """" CERTIFICATES """
    def getPublicKeyPKCS1(self):
        publicKey = {
            "modulus": self.n,
            "publicExponent": self.e
        }
        publicKey_ber = PKCS1_ENCODER.encode("RSAPublicKey", publicKey)
        publicKey = {
            "algorithm": {'algorithm': "1.2.840.113549.1.1.1", 'parameters': None},
            "publicKey": publicKey_ber
        }
        return publicKey_ber
    
    def sign(self, certificate_tbs_DER):
        # Calculate encryptWithPrivateKey(hash(certificate_tbs))
        certificate_hash = sha256(certificate_tbs_DER).digest()
        block_int = self.__encode(certificate_hash)
        c = PrimeUtils.square_n_multiply(block_int, self.d, self.n)
        return self.__decode(c, self.BLOCK_SIZE)

    def verifySignature(self, certificate_tbs, signature):
        # Calculate hash(certificate)
        certificate_hash = sha256(certificate_tbs).digest()

        # Calculate decryptWithPublicKey(signature)
        block_int = self.__encode(signature)
        c = PrimeUtils.square_n_multiply(block_int, self.e, self.n)
        decrypted_signature = self.__unpad(self.__decode(c, self.BLOCK_SIZE-1))

        # Compare
        return (certificate_hash == decrypted_signature)

    def setPublicKey(self, n, e):
        self.n = n
        self.e = e