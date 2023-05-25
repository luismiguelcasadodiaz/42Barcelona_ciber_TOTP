#!/Users/lcasado-/miniconda3/envs/42AI-lcasado-/bin/python
#!/home/luis/anaconda3/envs/42AI-lcasado-/bin/python

import os
import sys
import argparse
import hashlib
import warnings as _warnings
from cryptography.fernet import Fernet     # to cyfer Key into ft_otp.key
import base64
import hmac
import datetime
import binascii
import ssl

TIME_STEP = 30  # seconds
TOTP_LENGTH = 6
TOTP_DIVISOR = 10 ** TOTP_LENGTH


def generate_random_key(len=40):
    """
        Uses ssl.RAND_bytes
        randomly generates len bytes in the range
        Dec 32 .. Dec 126 ASCII printable characters.

        these bytes encoded base 32 forms a key

        Key is written in ft_rand.key
    PARAMS
        len = integer
    RETURNS
        pathfile to file containing random Key
    """

    random_key_b = b''
    count = 0
    while count <= len:
        v = ssl.RAND_bytes(1)
        if 32 <= v[0] and v[0] <= 126:
            random_key_b = random_key_b + v
            count = count + 1

    random_key_b32 = base64.b32encode(random_key_b)
    cwd = os.getcwd()
    pathfile = os.path.join(cwd, 'ft_rand.key')
    with open(pathfile, 'wb') as f:
        f.write(random_key_b32)
    return pathfile


def user_correct_length(argument):
    """
        Encodes the user PHEASE int a base 32 alfabet
        writes the key into ft_user.hex
    PARAMS
        argument : a PHRASE that user passes inside CLI
    RETURNS
        pathfile to file containing random Key
    """
    user_key_b = bytearray(argument, 'utf-8')
    user_key_b32 = base64.b32encode(user_key_b)
    cwd = os.getcwd()
    pathfile = os.path.join(cwd, 'ft_user.key')
    with open(pathfile, 'wb') as f:
        f.write(user_key_b32)
    return pathfile


def correct_length(file):
    """
        helper function checks if Hexadecimal key is longer than 64
    """
    # 1.- check if key exist
    cwd = os.getcwd()
    pathfile = os.path.join(cwd, file)
    if os.path.isfile(pathfile):
        # 2.- check if i can read the key
        if os.access(pathfile, os.R_OK):
            # 3.- read the file and check length
            with open(pathfile, 'rb') as f:
                text = f.read().strip()  # remove \n: does not belong to Key
                # text = b'aaaabbbbccccddddeeeeffffgggghhhh'
            # 4.- if length is ok
            size = len(text)
            if size >= 64:
                # 4bis.- size has to be a multiple of 4.
                if (size % 4) == 0:
                    # 5.- if it is a hexadecimal string.
                    is_base32 = True
                    hex_chars = b'0123456789ABCDEF'
                    for char in text.upper():
                        if char not in hex_chars:
                            is_base32 = False
                            break
                    del text
                    if is_base32:
                        return pathfile
                    else:
                        parser.error("Key is not an Hexadecimal File")
                else:
                    msg = f"Key Length {size} must be a multiple of 4"
                    parser.error(msg)
            else:
                parser.error(f"Key lenght of {size} is smaller than 64")
        else:
            parser.error(f"Can not read {pathfile}")
    else:
        parser.error(f"File {pathfile} does not exist")


def correct_filename(argument):
    """
        Checks if a file exists and can be read.
    PARAMS:
        Argument : Pathfile to cyphered secret key
    """
    if argument is None:
        parser.error(f"Missing file name '{argument}'")
    else:
        try:
            cwd = os.getcwd()
            filepath = os.path.join(cwd, argument)
            if os.path.isfile(filepath):
                if not os.access(filepath, os.R_OK):
                    parser.error(f"can not read'{argument}'")
                else:
                    return filepath
        except FileNotFoundError:
            parser.error(f"Can not find '{argument}'")


def create_argument_parser():

    msg = """
    Permet d’enregistrer un mot de passe initial, et qui est capable"
    de générer un nouveau mot de passe chaque fois qu’il est demandé"""
    parser = argparse.ArgumentParser(
        prog='ft_otp',
        description=msg,
        epilog='Este es el final de la ayuda',
        usage="""
        ./ft_otp -g HEXFILE |
        ./ft_otp -u PHRASE |
        ./ft_otp -r |
        ./ft_otp -k ft_otp.key |
        ./ft_otp -s ft_otp.key |
        --GUI
        --show
        """
        )
    parser.add_argument('--show', help='Shows secret key', action='store_true')

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument('-s',
                       help=f'With ciphered file ft_otp.key, TOTP sequence.',
                       type=correct_filename)
    group.add_argument('-k',
                       help=f'With a ciphered file ft_otp.key, next TOTP.',
                       type=correct_filename)
    group.add_argument('-g',
                       help='Clave hexadecimal > 64 caracters en ft_hex.key',
                       type=correct_length)
    group.add_argument('-u',
                       help='Frase del usuario para generar un ft_user.key',
                       type=user_correct_length)
    group.add_argument('-r',
                       help='Aleatoriamente genero una clave en ft_rand.key',
                       action='store_true')
    group.add_argument('--GUI',
                       help='Ejecuta la aplicacion con un interface grafico',
                       action='store_true')
    return parser


def encrypt_key(path_to_key):
    path_file = os.path.split(path_to_key)
    path = path_file[0]

    # get the key i will use to seed cifer tool
    cwd = os.getcwd()
    cifer_key_path = os.path.join(os.environ["HOME"], ".ssh/.encrypt.key")
    try:

        with open(cifer_key_path, 'rb') as f:
            cifer_key = f.read()

        # initialize encrypter wiht the key
        fernet = Fernet(cifer_key)

        # get the key in ft_otp.hex i have to save into ft_otp.key cyphered#
        with open(path_to_key, 'rb') as f:
            totp_key_to_encrypt = f.read().strip()

        totp_key_encrypted = fernet.encrypt(totp_key_to_encrypt)

        # write into ft_otp.key the cyphered#"
        with open(os.path.join(path, "ft_otp.key"), 'bw') as f:
            f.write(totp_key_encrypted)
        msg = "ft_otp.Key has been created"
        print(msg)
    except FileNotFoundError:
        msg = "Encription Key not found. Execute 'generate_encrypt_key.py'"
        print(msg)


def decrypt_key(path_to_key):
    path_file = os.path.split(path_to_key)
    path = path_file[0]

    # read the key used to seed cifer tool
    cifer_key_path = os.path.join(os.environ["HOME"], ".ssh/.encrypt.key")
    try:
        with open(cifer_key_path, 'rb') as f:
            cifer_key = f.read()
    except FileNotFoundError:
        msg = f"Not found {cifer_key_path}. "
        msg = msg + "Execute 'generate_encrypt_key.py"
        raise ValueError(msg)

    # initialize encrypter wiht the key
    fernet = Fernet(cifer_key)

    # read TOTP encrypted key
    with open(path_to_key, 'br') as f:
        totp_key_encrypted = f.read()

    # decrypt TOTP Key
    key_cyphered = fernet.decrypt(totp_key_encrypted)

    return key_cyphered


def get_totp_token(secret):
    try:
        # Encode the secret into a base 32 string
        secret_b32 = base64.b32decode(secret.decode(), True, map01='l')

    except binascii.Error:
        secret_b32 = base64.b64decode(secret.decode())
        print("secret b32 = ", secret_b32)
    # Calculate number of time steps since beginin of time in UTC time Zone
    int_dt_utc = int(datetime.datetime.now(datetime.timezone.utc).timestamp())

    N = int_dt_utc // TIME_STEP   # Num of intervals

    # Convert the number of time steps into an 8 bytes hexadecinal string value
    m = int.to_bytes(N, length=8, byteorder='big')

    # HOTP Value generation RFC 4226 5.2. Description

    # Step 1: Generate an HMAC-SHA-1 value Let HS = HMAC-SHA-1(K,C)
    # // HS  is a 20-byte string

    # Hash the number of time steps wiht the secret
    hash = hmac.new(secret_b32, m, hashlib.sha1).digest()

    # Step 2:Generate a 4-byte string (Dynamic Truncation)
    # get the offset form the last nibble
    offset = digest_last_nibble = hash[19] & 0xF     # xxxx and 1111

    signed_4b_hash = hash[offset:offset + 4]     # 4 bytes start in offset

    # Step 3: Compute an HOTP value
    mask = bytes.fromhex('7fffffff')

    un_signed_4b_hash = bytes([h & m for h, m in zip(signed_4b_hash, mask)])

    gross_totp = int.from_bytes(un_signed_4b_hash, byteorder='big')
    # get the lest significative digites
    net_totp = gross_totp % TOTP_DIVISOR

    # in case i got less than 6 digits
    str_totp = str(net_totp)

    while len(str_totp) < TOTP_LENGTH:
        str_totp = '0' + str_totp
    return str_totp


if __name__ == "__main__":
    parser = create_argument_parser()
    args = parser.parse_args(sys.argv[1:])
    print("Estos son mis argumentos ", args)
    if args.GUI:
        print("Me han pedido que me ejecute en modo grafico")
    else:
        if args.g is not None:
            msg = f"Me han dado una clave {args.g} para que la guarde "
            msg = msg + "cifrada en ft_otp.key"
            print(msg)
            encrypt_key(args.g)
        if args.u is not None:
            msg = "Me han dado una clave texto plano del usuario "
            msg = msg + f"> {args.u} <. Guardada ft_user.key"
            print(msg)
            encrypt_key(args.u)

        if args.r:   # flag store action true
            msg = "Me han pedido una clave aleatoria "
            msg = msg + "que he guardado en ft_rand.key"
            print(msg)
            file = generate_random_key()
            encrypt_key(file)
        if args.k is not None:
            msg = "Me han dado pedido el proximo OTP basado "
            msg = msg + f"en {args.k}"
            print(msg)
            totp_key = decrypt_key(args.k)
            if args.show:
                print(f"Secret Key = {totp_key}")
            print(get_totp_token(totp_key))
        if args.s is not None:
            msg = "Me han dado pedido secuencia de OTP basado "
            msg = msg + f"en {args.s}"
            print(msg)
            totp_key = decrypt_key(args.s)
            if args.show:
                print(f"Secret Key = {totp_key}")
            totp = get_totp_token(totp_key)
            print(totp, end="\n")
            print("-" * TOTP_LENGTH, end="\n")
            s = int(datetime.datetime.now(datetime.timezone.utc).timestamp())

            while True:
                aux = datetime.datetime.now(datetime.timezone.utc)
                n = int(aux.timestamp())
                elapsed_time = n - s
                if elapsed_time == TIME_STEP:
                    totp = get_totp_token(totp_key)
                    print(totp, "               ", end="\n")
                    print("-" * TOTP_LENGTH, end="\n")
                    s = n
                else:
                    msg = f"Elapsed_time:{TIME_STEP - elapsed_time:0>2}"
                    print(msg, end="\r")
