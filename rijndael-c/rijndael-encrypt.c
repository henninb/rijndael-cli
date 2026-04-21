#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include "rijndael-api-fst.h"

#define KEY_SIZE_BITS 256
#define IV_SIZE_BITS  128
#define BLOCK_SIZE    128
#define MAC_SIZE       64

void fileWrite( char *, BYTE *, int );
void fileRead( char *, BYTE *, int );
long fileLength( char * );
void hexToBytes( const BYTE *, BYTE *, int );

int main( int argc, char *argv[] ) {
  int rc;
  keyInstance key_ptr;
  cipherInstance *cipher_ptr;
  BYTE *cipherText;
  BYTE *plainText;
  BYTE *key_text;
  BYTE *iv_text;
  char *ifname, *ofname, *keyfname, *ivfname;
  int ofsize, nfsize, idx_i;
  BYTE key_bytes[KEY_SIZE_BITS/8];
  unsigned char mac[MAC_SIZE];
  unsigned int mac_len = MAC_SIZE;
  char sig_fname[512];

  if( argc != 5 ) {
    fprintf( stderr, "Usage: %s <ifname> <ofname> <key> <iv>\n", argv[0] );
    exit( 1 );
  }

  ifname   = argv[1];
  ofname   = argv[2];
  keyfname = argv[3];
  ivfname  = argv[4];

  printf("[ C | encrypt ] algorithm  : AES-%d/CBC/PKCS7\n", KEY_SIZE_BITS);

  key_text = (BYTE *) malloc(KEY_SIZE_BITS/8 * 2 + 1);
  if( key_text == NULL ) { fprintf(stderr, "ABORT: malloc failed.\n"); exit(1); }
  memset(key_text, '\0', KEY_SIZE_BITS/8 * 2 + 1);
  fileRead(keyfname, key_text, KEY_SIZE_BITS/8 * 2);

  iv_text = (BYTE *) malloc((IV_SIZE_BITS/8) * 2 + 1);
  if( iv_text == NULL ) { fprintf(stderr, "ABORT: malloc failed.\n"); exit(1); }
  memset(iv_text, '\0', (IV_SIZE_BITS/8) * 2 + 1);
  fileRead(ivfname, iv_text, IV_SIZE_BITS/8 * 2);

  ofsize = fileLength(ifname);
  nfsize = ofsize + ((BLOCK_SIZE/8) - (ofsize % (BLOCK_SIZE/8)));
  printf("[ C | encrypt ] input      : %d bytes  ->  padded : %d bytes\n", ofsize, nfsize);

  cipherText = (BYTE *)malloc(nfsize);
  if( cipherText == NULL ) { fprintf(stderr, "ABORT: malloc failed.\n"); exit(1); }
  plainText = (BYTE *)malloc(nfsize);
  if( plainText == NULL ) { fprintf(stderr, "ABORT: malloc failed.\n"); exit(1); }

  memset(plainText,  '\0', nfsize);
  memset(cipherText, '\0', nfsize);
  fileRead(ifname, plainText, ofsize);

  for( idx_i = ofsize; idx_i < nfsize; idx_i++ )
    plainText[idx_i] = nfsize - ofsize;

  cipher_ptr = (cipherInstance *)malloc( sizeof(cipherInstance));
  if( cipher_ptr == NULL ) { fprintf(stderr, "ABORT: malloc failed.\n"); exit(1); }
  if( (rc = cipherInit( cipher_ptr, MODE_CBC, iv_text )) < 0 ) {
    fprintf( stderr, "ABORT: cipherInit() failed: %d\n", rc ); exit(rc);
  }
  if( (rc = makeKey( &key_ptr, DIR_ENCRYPT, KEY_SIZE_BITS, key_text )) < 0 ) {
    fprintf( stderr, "ABORT: makeKey() failed: %d\n", rc ); exit(rc);
  }
  if( (rc = blockEncrypt( cipher_ptr, &key_ptr, plainText, 8 * nfsize, cipherText)) < 1 ) {
    fprintf( stderr, "ABORT: blockEncrypt() failed: %d\n", rc); exit(rc);
  }

  fileWrite(ofname, cipherText, nfsize);
  printf("[ C | encrypt ] output     : %s\n", ofname);

  hexToBytes(key_text, key_bytes, KEY_SIZE_BITS/8);
  HMAC(EVP_sha512(), key_bytes, KEY_SIZE_BITS/8, cipherText, nfsize, mac, &mac_len);
  snprintf(sig_fname, sizeof(sig_fname), "%s.sig", ofname);
  fileWrite(sig_fname, mac, MAC_SIZE);
  printf("[ C | encrypt ] signature  : written\n");

  memset(key_bytes,  0, sizeof(key_bytes));
  memset(mac,        0, sizeof(mac));
  memset(key_text,   0, KEY_SIZE_BITS/8 * 2 + 1);
  memset(iv_text,    0, (IV_SIZE_BITS/8) * 2 + 1);
  memset(&key_ptr,   0, sizeof(keyInstance));
  memset(cipher_ptr, 0, sizeof(cipherInstance));
  free(key_text); free(iv_text); free(plainText); free(cipherText); free(cipher_ptr);

  return 0;
}

void hexToBytes( const BYTE *hex, BYTE *out, int nbytes ) {
  for( int i = 0; i < nbytes; i++ ) {
    unsigned int b;
    sscanf((const char*)hex + i*2, "%02x", &b);
    out[i] = (BYTE)b;
  }
}

void fileWrite( char *ifname, BYTE *istring, int istring_sz ) {
  FILE *ifp;
  if((ifp = fopen( ifname, "wb" )) == NULL ) {
    fprintf( stderr, "ABORT: fopen() failed for '%s'.\n", ifname ); exit(1);
  }
  if( fwrite( istring, 1, istring_sz, ifp ) != (size_t)istring_sz ) {
    fprintf( stderr, "ABORT: fwrite() failed for '%s'.\n", ifname ); exit(1);
  }
  fclose( ifp );
}

void fileRead( char *ifname, BYTE *ostring, int ostring_sz ) {
  int read_in = 0, fsize = 0;
  FILE *ifp;
  if((ifp = fopen( ifname, "rb" )) == NULL ) {
    fprintf( stderr, "ABORT: fopen() failed for '%s'.\n", ifname ); exit(1);
  }
  while( fsize < ostring_sz &&
         (read_in = fread( ostring + fsize, 1, ostring_sz - fsize, ifp )) > 0 )
    fsize += read_in;
  fclose( ifp );
}

long fileLength( char *fname ) {
  struct stat file_stat;
  if( stat( fname, &file_stat ) != 0 ) {
    fprintf( stderr, "ABORT: stat() failed.\n" ); exit(1);
  }
  return file_stat.st_size;
}
