# cryptofile
Encrypto/Decrypto file using AES

## Install

Install following module.
- pycrypto

## Usage

* Encrypto

```
$ python cryptofile.py myfile myfile.enc
```

* Decrypto

```
$ python cryptofile.py --dec myfile.enc myfile.dec
$ diff myfile myfile.dec
```

