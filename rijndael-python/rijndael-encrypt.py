#!/usr/bin/env python3

import hashlib
import hmac as hmac_mod
import os
import sys
from Crypto.Cipher import AES

def fileRead(ifname):
  with open(ifname, 'rb') as ifp:
    return ifp.read()

def fileWrite(ofname, data):
  with open(ofname, "wb") as ofp:
    ofp.write(data)

def rijndael_encrypt(ifname, ofname, keyfname, ivfname):
  plainText = bytearray(fileRead(ifname))
  key_hex = fileRead(keyfname)
  iv_hex = fileRead(ivfname)
  BLOCK_SIZE = 128

  original_fsize = len(plainText)
  pad_len = (BLOCK_SIZE // 8) - (original_fsize % (BLOCK_SIZE // 8))
  new_fsize = original_fsize + pad_len

  plainText += bytes([pad_len] * pad_len)

  key = bytearray(bytes.fromhex(key_hex.decode().strip()))
  iv  = bytearray(bytes.fromhex(iv_hex.decode().strip()))

  print("[ Python | encrypt ] algorithm : AES-%d/CBC/PKCS7" % (len(key) * 8))
  print("[ Python | encrypt ] input     : %d bytes  ->  padded : %d bytes" % (original_fsize, new_fsize))

  try:
    cipher = AES.new(bytes(key), AES.MODE_CBC, bytes(iv))
    cipherText = cipher.encrypt(bytes(plainText))
    fileWrite(ofname, cipherText)
    print("[ Python | encrypt ] output    : %s" % ofname)

    sig = hmac_mod.new(bytes(key), cipherText, hashlib.sha512).digest()
    fileWrite(ofname + ".sig", sig)
    print("[ Python | encrypt ] signature : written")
  finally:
    key[:] = bytes(len(key))
    iv[:]  = bytes(len(iv))

def main():
  if len(sys.argv) != 5:
    print("Usage: %s <ifname> <ofname> <key> <iv>" % sys.argv[0], file=sys.stderr)
    sys.exit(1)
  rijndael_encrypt(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])

main()
