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

def rijndael_decrypt(ifname, ofname, keyfname, ivfname):
  cipherText = fileRead(ifname)
  key_hex = fileRead(keyfname)
  iv_hex  = fileRead(ivfname)

  original_fsize = len(cipherText)

  key = bytearray(bytes.fromhex(key_hex.decode().strip()))
  iv  = bytearray(bytes.fromhex(iv_hex.decode().strip()))

  print("[ Python | decrypt ] algorithm : AES-%d/CBC/PKCS7" % (len(key) * 8))
  print("[ Python | decrypt ] input     : %d bytes" % original_fsize)

  try:
    sig_file = ifname + ".sig"
    if not os.path.exists(sig_file):
      print("[ Python | decrypt ] ABORT     : MAC file not found: %s" % sig_file, file=sys.stderr)
      sys.exit(1)
    stored_mac   = fileRead(sig_file)
    computed_mac = hmac_mod.new(bytes(key), cipherText, hashlib.sha512).digest()
    if not hmac_mod.compare_digest(stored_mac, computed_mac):
      print("[ Python | decrypt ] ABORT     : MAC verification failed — ciphertext has been tampered with", file=sys.stderr)
      sys.exit(3)
    print("[ Python | decrypt ] MAC       : verified OK")

    cipher = AES.new(bytes(key), AES.MODE_CBC, bytes(iv))
    plainText = bytearray(cipher.decrypt(cipherText))

    idx_j = original_fsize
    while idx_j > 0 and plainText[idx_j - 1] == plainText[original_fsize - 1]:
      idx_j -= 1

    if (original_fsize - idx_j) != plainText[original_fsize - 1]:
      print("[ Python | decrypt ] ABORT     : invalid PKCS7 padding", file=sys.stderr)
      sys.exit(1)
    fileWrite(ofname, bytes(plainText[:idx_j]))
    print("[ Python | decrypt ] output    : %s" % ofname)
  finally:
    key[:] = bytes(len(key))
    iv[:]  = bytes(len(iv))

def main():
  if len(sys.argv) != 5:
    print("Usage: %s <ifname> <ofname> <key> <iv>" % sys.argv[0], file=sys.stderr)
    sys.exit(1)
  rijndael_decrypt(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])

main()
