# -*- coding: utf-8 -*-
from Crypto.Cipher import AES
import argparse
import getpass

key_size = 32
iv = 'penpineapplepen!'.encode('utf-8')

def create_key(p_key):
    key_size_fill = p_key.zfill(key_size)
    key = key_size_fill[:key_size].encode('utf-8')
    return key


def encrypt(data, p_key, output_file=None):
    key = create_key(p_key)
    obj = AES.new(key, AES.MODE_CFB, iv)

    ret_bytes = obj.encrypt(data)

    if output_file is not None:
        with open(output_file, "wb") as fout:
            fout.write(ret_bytes)

    return ret_bytes


def decrypt(data, p_key, output_file=None):
    key = create_key(p_key)
    obj = AES.new(key, AES.MODE_CFB, iv)
    ret_bytes = obj.decrypt(data)

    if output_file is not None:
        with open(output_file, "wb") as fout:
            fout.write(ret_bytes)


def encrypt_from_file(input_data_file_name, output_data_file_name, password):
    with open(input_data_file_name, "rb") as df:
        str_file_data = df.read()

    return encrypt(str_file_data, password, output_file=output_data_file_name)


def decrypt_from_file(data_file_path, output_data_file_name, password):
    with open(data_file_path, "rb") as df:
        byte = df.read()

    return decrypt(byte, password, output_file=output_data_file_name)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Offset value simulation')
    parser.add_argument('input_file', metavar="INPUT_FILE", type=str,  default=None,
                        help='Input file')
    parser.add_argument('output_file', metavar="OUTPUT_FILE", type=str,  default=None,
                        help='Output file')
    parser.add_argument('--dec', action='store_true', help='Decrypto file')
    args = parser.parse_args()
    password = getpass.getpass('password:')
    if args.dec:
        # decrypto
        decrypt_from_file(args.input_file, args.output_file, password)
    else:
        # encrypto
        encrypt_from_file(args.input_file, args.output_file, password)
    


