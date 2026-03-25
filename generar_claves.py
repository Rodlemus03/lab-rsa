from Crypto.PublicKey import RSA

def generar_par_claves(bits: int = 3072):
    if bits < 2048:
        raise ValueError("RSA requiere al menos 2048 bits para este laboratorio")

    key = RSA.generate(bits)
    private_key = key.export_key(
        format="PEM",
        passphrase="lab04uvg",
        pkcs=8,
        protection="scryptAndAES128-CBC",
    )
    public_key = key.publickey().export_key(format="PEM")

    with open("private_key.pem", "wb") as private_file:
        private_file.write(private_key)

    with open("public_key.pem", "wb") as public_file:
        public_file.write(public_key)

    return private_key, public_key

if __name__ == '__main__':
    generar_par_claves(3072)
    print("Claves generadas: private_key.pem y public_key.pem")
