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
long filelen( char * );
void hexToBytes( const BYTE *, BYTE *, int );

int main( int argc, char *argv[] ) {
  int rc;
  keyInstance key_ptr;
  cipherInstance *cipher_ptr;
  BYTE *cipherText, *plainText, *key_text, *iv_text;
  char *ifname, *ofname, *keyfname, *ivfname;
  int original_fsize, idx_i;
  BYTE key_bytes[KEY_SIZE_BITS/8];
  char sig_fname[512];
  struct stat sig_stat;

  if( argc != 5 ) {
    fprintf( stderr, "Usage: %s <ifname> <ofname> <key> <iv>\n", argv[0] );
    exit( 1 );
  }

  ifname   = argv[1];
  ofname   = argv[2];
  keyfname = argv[3];
  ivfname  = argv[4];

  printf("[ C | decrypt ] algorithm  : AES-%d/CBC/PKCS7\n", KEY_SIZE_BITS);

  key_text = (BYTE *) malloc(KEY_SIZE_BITS/8 * 2 + 1);
  if( key_text == NULL ) { fprintf(stderr, "ABORT: malloc failed.\n"); exit(1); }
  memset(key_text, '\0', KEY_SIZE_BITS/8 * 2 + 1);
  fileRead(keyfname, key_text, KEY_SIZE_BITS/8 * 2);

  iv_text = (BYTE *) malloc((IV_SIZE_BITS/8) * 2 + 1);
  if( iv_text == NULL ) { fprintf(stderr, "ABORT: malloc failed.\n"); exit(1); }
  memset(iv_text, '\0', (IV_SIZE_BITS/8) * 2 + 1);
  fileRead(ivfname, iv_text, IV_SIZE_BITS/8 * 2);

  cipher_ptr = (cipherInstance *)malloc( sizeof(cipherInstance));
  if( cipher_ptr == NULL ) { fprintf(stderr, "ABORT: malloc failed.\n"); exit(1); }
  if( (rc = cipherInit( cipher_ptr, MODE_CBC, iv_text )) < 0 ) {
    fprintf( stderr, "ABORT: cipherInit() failed: %d\n", rc ); exit(rc);
  }

  original_fsize = filelen(ifname);
  printf("[ C | decrypt ] input      : %d bytes\n", original_fsize);

  cipherText = (BYTE *)malloc( original_fsize + 1 );
  if( cipherText == NULL ) { fprintf(stderr, "ABORT: malloc failed.\n"); exit(1); }
  plainText = (BYTE *)malloc( original_fsize + 1 );
  if( plainText == NULL ) { fprintf(stderr, "ABORT: malloc failed.\n"); exit(1); }

  memset(cipherText, '\0', original_fsize + 1);
  memset(plainText,  '\0', original_fsize + 1);
  fileRead(ifname, cipherText, original_fsize);

  hexToBytes(key_text, key_bytes, KEY_SIZE_BITS/8);
  snprintf(sig_fname, sizeof(sig_fname), "%s.sig", ifname);
  if( stat(sig_fname, &sig_stat) != 0 ) {
    fprintf(stderr, "ABORT: MAC file not found: %s\n", sig_fname); exit(1);
  }
  {
    BYTE stored_mac[MAC_SIZE];
    unsigned char computed_mac[MAC_SIZE];
    unsigned int mac_len = MAC_SIZE;
    fileRead(sig_fname, stored_mac, MAC_SIZE);
    HMAC(EVP_sha512(), key_bytes, KEY_SIZE_BITS/8, cipherText, original_fsize, computed_mac, &mac_len);
    if( CRYPTO_memcmp(stored_mac, computed_mac, MAC_SIZE) != 0 ) {
      fprintf(stderr, "ABORT: MAC verification failed\n"); exit(1);
    }
    printf("[ C | decrypt ] MAC        : verified OK\n");
  }
  memset(key_bytes, 0, sizeof(key_bytes));

  if( (rc = makeKey( &key_ptr, DIR_DECRYPT, KEY_SIZE_BITS, key_text )) < 0 ) {
    fprintf( stderr, "ABORT: makeKey() failed: %d\n", rc ); exit(rc);
  }
  if( (rc = blockDecrypt( cipher_ptr, &key_ptr, cipherText, 8 * original_fsize, plainText)) < 1 ) {
    fprintf( stderr, "ABORT: blockDecrypt() failed: %d\n", rc ); exit(rc);
  }

  idx_i = original_fsize;
  while( idx_i > 0 && plainText[idx_i - 1] == plainText[original_fsize - 1] )
    idx_i--;

  if( (original_fsize - idx_i) != plainText[original_fsize - 1] ) {
    fprintf(stderr, "ABORT: invalid PKCS7 padding\n"); exit(1);
  }
  fileWrite(ofname, plainText, idx_i);

  printf("[ C | decrypt ] output     : %s\n", ofname);

  memset(key_text,   0, KEY_SIZE_BITS/8 * 2 + 1);
  memset(iv_text,    0, (IV_SIZE_BITS/8) * 2 + 1);
  memset(&key_ptr,   0, sizeof(keyInstance));
  memset(cipher_ptr, 0, sizeof(cipherInstance));
  free(key_text); free(iv_text); free(cipherText); free(plainText); free(cipher_ptr);

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

long filelen( char *fname ) {
  struct stat file_stat;
  if( stat( fname, &file_stat ) != 0 ) {
    fprintf( stderr, "ABORT: stat() failed.\n" ); exit(1);
  }
  return file_stat.st_size;
}
