/* 
 * spor.h 
 */

#ifndef SPOR_H
#define SPOR_H

#define CRYPTO "ltc_argon"


#if BACKEND == "ltc_argon"
/* use this math library */
#define MATH            gmp_desc

/* entropy minimums */
#define ENTROPY_SOURCE  "/dev/urandom"
#define MIN_ENTROPY     16
#define SALTSZ          16    

/* algorithm selection */
#define PRNG            fortuna_desc
#define CIPHER          aes_desc
#define HASH            sha256_desc

#define ARGON_TCOST     10    
#define ARGON_MCOST     1<<18  /* (=256M) */
#define ARGON_PARALLEL  4 

/* must match algorithm block sizes above */
#define KEYSZ_SYM       32     /* 256 bits */    
#define KEYSZ_PK        65     /* 521 bits */

/* on-disk format */
#define MAGIC "s0"
#define SPOR_ONDISK_VERSION 0x01

struct asymkey;

#endif


/* miscellany */
#define BUFSZ           224    /* encrypted keys, password and key m/xports */
#define STACK_BURN_KB   20     /* determined with test_stack.sh */




/**
 ** common code (implemented in spor.c)
 **/

void s0_encrypt_stream (
  const int infd,  
  const int outfd, 
  unsigned char *pwbuf, 
  const unsigned len
);
void s0_decrypt_stream(
  const int infd, 
  const int outfd, 
  unsigned char *pwbuf, 
  const unsigned len
);

void s0_hash_stream(
  const int infd, 
  unsigned char *hash, 
  unsigned sz
);

void s0_sign_stream(
  struct asymkey *akey, 
  const int infd, 
  const int sigfd
);

void s0_verify_stream(
  struct asymkey *akey, 
  const int infd, 
  const int sigfd
);

void s0_asym_encrypt_stream(
  struct asymkey *akey, 
  const int infd, 
  const int outfd
);

void s0_asym_decrypt_stream(
  struct asymkey *akey, 
  const int infd, 
  const int outfd
);

void s0_create_key(
  struct asymkey *akeyp
);
void s0_import_key(
  struct asymkey *akeyp, 
  const int infd, 
  unsigned char *pwbuf, 
  const unsigned len
);
void s0_export_key(
  struct asymkey *akeyp, 
  const int outfd, 
  unsigned char *pwbuf,  
  const unsigned len
);

/**
 ** backend-specific code (in spor_*.c)
 **/

void s0_setup (void);
void s0_teardown(void);

void s0_prng_init(void);
void s0_prng_getbytes (
  unsigned char *buf, 
  const int buflen
);
void s0_prng_done(void);

void s0_cipher_init(
  const unsigned char *key, 
  const unsigned char *iv, 
  const int sz
);
void s0_cipher_encrypt(
  unsigned char *buf, 
  const unsigned sz
);
void s0_cipher_decrypt(
  unsigned char *buf, 
  const unsigned sz
);
void s0_cipher_done(void);

void s0_hash_init(void);
void s0_hash_update(
  const unsigned char *buf, 
  const unsigned sz
);
void s0_hash_done(
  unsigned char *buf, 
  const unsigned sz
);
unsigned s0_hash_size(void);

void s0_asym_keygen(
  struct asymkey *akeyp
);
void s0_asym_import(
  const unsigned char *buf, 
  const unsigned len, 
  struct asymkey *akeyp
);
void s0_asym_export(
  unsigned char *buf, 
  long unsigned *szp, 
  const unsigned type, 
  struct asymkey *akeyp
);

void s0_asym_sign(
  struct asymkey *akeyp, 
  const unsigned char *hash, 
  const int hashsz, 
  unsigned char *sig, 
  long unsigned *sigszp
);
int s0_asym_verify(
  struct asymkey *akeyp, 
  const unsigned char *hash, 
  const int hashsz, 
  const unsigned char *sig, 
  const unsigned sigsz
);

void s0_asym_encrypt_key(
  struct asymkey *akeyp, 
  const unsigned char *skey, 
  const unsigned ssz, 
  unsigned char *cryptbuf, 
  unsigned long *cryptszp
);
void s0_asym_decrypt_key(
  struct asymkey *akeyp, 
  unsigned char *skey,  
  unsigned long ssz, 
  const unsigned char *cryptbuf, 
  const unsigned long cryptsz
);


#endif
