/*
 * spor_ltc.c
 * crypto functions with libtomcrypt
 */

#include <fcntl.h>
#include <unistd.h>

#include <tomcrypt.h>

#include "spor.h"
#include "spor_ltc.h"
#include "util.h"


#define DIET(err, msg) fprintf(stderr, "died in %s: %s\n", msg, error_to_string(err)),exit(2)


struct s0_profile {
  int prng_ok;
  prng_state prng;
  symmetric_CTR cipher_state;
  hash_state hash;
  unsigned char prng_idx;
  unsigned char cipher_idx;
  unsigned char hash_idx;
};

struct s0_profile prof;     /* global state */


/**
 ** Housekeeping
 **/


void s0_setup (void) {
  int err;
  ltc_mp = MATH;
  if ( (err=register_prng(&PRNG)) != CRYPT_OK ) DIET(err, "register_prng");
  if ( (err=register_cipher(&CIPHER)) != CRYPT_OK ) DIET(err, "register_cipher");
  if ( (err=register_hash(&HASH)) != CRYPT_OK ) DIET(err, "register_hash");
  zeromem(&prof, sizeof(prof));
}

void s0_teardown(void) {
  s0_prng_done();
  zeromem(&prof, sizeof(prof));
}


/**
 ** RNG primitives
 **/

void s0_prng_init(void) {
  unsigned char entropy[MIN_ENTROPY];
  int random_fd, len, err;
  struct ltc_prng_descriptor *prngp = &prng_descriptor[prof.prng_idx];  

  if ( prof.prng_ok ) return;

  /* get some entropy from the OS */
  if ( (random_fd=open(ENTROPY_SOURCE, O_RDONLY)) < 0 ) DIES("opening " ENTROPY_SOURCE);
  len = read_or_die(random_fd, entropy, sizeof(entropy), "reading_entropy");
  if ( len < sizeof(entropy) ) DIES("insufficient entropy");
  close(random_fd); 
  
  /* prepare the prng */
  if ( (err=prngp->start(&prof.prng)) != CRYPT_OK )  DIET(err,"prng.start");  
  if ( (err=prngp->add_entropy(entropy, sizeof(entropy), &prof.prng)) ) DIET(err,"prng.add_entropy");
  if ( (err=prngp->ready(&prof.prng)) ) DIET(err,"prng.ready");

  prof.prng_ok = 1;
  /* cleanup*/
  zeromem(entropy, sizeof(entropy));
}

void s0_prng_getbytes (unsigned char *buf, const int buflen) {
  int err;

  if ( !prof.prng_ok ) s0_prng_init();
  struct ltc_prng_descriptor *prngp = &prng_descriptor[prof.prng_idx];  
  if ( (err=prngp->read(buf, buflen, &prof.prng)) != buflen ) DIET(err,"prng.read");
}

void s0_prng_done(void) {
  struct ltc_prng_descriptor *prngp = &prng_descriptor[prof.prng_idx];  
  if ( prof.prng_ok )  prngp->done(&prof.prng);
  prof.prng_ok = 0;
}


/**
 ** Symmetric primitives
 **/
void s0_cipher_init(const unsigned char *key, const unsigned char *iv, 
                    const int sz) {
  int err;
  if ( (err=ctr_start(prof.cipher_idx, iv, key, sz, 0, 
       CTR_COUNTER_LITTLE_ENDIAN, 
       &prof.cipher_state)) != CRYPT_OK ) DIET(err,"ctr_start");
}

void s0_cipher_encrypt(unsigned char *buf, const unsigned sz) {
  int err;
  if ( (err=ctr_encrypt(buf, buf, sz, &prof.cipher_state)) != CRYPT_OK) DIET(err,"encrypt");
}

void s0_cipher_decrypt(unsigned char *buf, const unsigned sz) {
  int err;
  if ( (err=ctr_decrypt(buf, buf, sz, &prof.cipher_state)) != CRYPT_OK ) DIET(err,"decrypt");
}

void s0_cipher_done() {
  int err;
  if ( (err=ctr_done(&prof.cipher_state)) != CRYPT_OK ) DIET(err, "ctr_done");
}


/**
 ** Hashing primitives
 **/

void s0_hash_init(void) {
  int err;
  struct ltc_hash_descriptor hash = hash_descriptor[prof.hash_idx];  
  if ( (err=hash.init(&prof.hash)) != CRYPT_OK ) DIET(err, "hash init");
}

void s0_hash_update(const unsigned char *buf, const unsigned sz) {
  int err;
  struct ltc_hash_descriptor hash = hash_descriptor[prof.hash_idx];
  if ( (err=hash.process(&prof.hash, buf, sz)) != CRYPT_OK ) DIET(err, "hash process");  
}

void s0_hash_done(unsigned char *buf, const unsigned sz) {
  int err;
  struct ltc_hash_descriptor *hash = &hash_descriptor[prof.hash_idx];  
  if ( sz < hash->hashsize )  DIE("Buffer overflow");
  if ( (err=hash->done(&prof.hash, buf)) != CRYPT_OK ) DIET(err, "hash done");
}

unsigned s0_hash_size(void) {
  return hash_descriptor[prof.hash_idx].hashsize;
}


/**
 ** PK primitives
 **/

void s0_asym_setup(struct asymkey *akeyp) {
  akeyp->ready = 0;
}

void s0_asym_keygen(struct asymkey *akeyp) {
  int err;
  s0_prng_init();
  if ( (err=ecc_make_key(&prof.prng, prof.prng_idx, KEYSZ_PK, &akeyp->key))
        != CRYPT_OK) DIET(err,"ecc_make_key");
  akeyp->ready = 1;
}

void s0_asym_import (const unsigned const char *buf, unsigned len, 
                     struct asymkey *akeyp) {
  int err;
  if ( (err=ecc_import(buf, len, &akeyp->key)) != CRYPT_OK)
    DIET(err, "ecc_import (bad passphrase?)");
  akeyp->ready = 1;
}

void s0_asym_export (unsigned char *buf, long unsigned *szp, 
                     const unsigned export_private, struct asymkey *akeyp) {
  int err, type;
  if ( ! akeyp->ready ) DIE("no key loaded");
  type = (export_private) ? PK_PRIVATE : PK_PUBLIC;
  if ( (err=ecc_export(buf, szp, type, &akeyp->key)) != CRYPT_OK) {
    DIET(err,"ecc_export(private)");
  }

}

void s0_asym_sign(struct asymkey *akeyp, const unsigned char *hash, const int hashsz, 
                  unsigned char *sig, long unsigned *sigszp) {
  int err;
  if ( ! akeyp->ready ) DIE("no key loaded");
  s0_prng_init();
  if ( (err=ecc_sign_hash(
         hash, hashsz, sig, sigszp, 
         &prof.prng, prof.prng_idx, &akeyp->key)
       ) != CRYPT_OK ) DIET(err, "ecc_sign_hash");
}

int s0_asym_verify(struct asymkey *akeyp, const unsigned char *hash, const int hashsz, 
                   const unsigned char *sig, const const unsigned sigsz) {
  int err;
  int stat;
  if ( ! akeyp->ready ) DIE("no key loaded");
  if ( (err=ecc_verify_hash(sig, sigsz, hash, hashsz,
         &stat, &akeyp->key)
       ) != CRYPT_OK ) DIET(err, "ecc_verify_hash");
  return stat;
}

void s0_asym_encrypt_key(struct asymkey *akeyp, 
                         const unsigned char *skey, const unsigned ssz, 
                         unsigned char *cryptbuf, unsigned long *cryptszp) {
  int err;
  if ( ! akeyp->ready ) DIE("no key loaded");
  s0_prng_init();
  assert (ssz >0);
  if ( (err=ecc_encrypt_key(skey, ssz, cryptbuf, cryptszp, 
        &prof.prng, prof.prng_idx, prof.hash_idx, &akeyp->key)) != CRYPT_OK ) DIET(err, "ecc_encrypt_key"); 
}

void s0_asym_decrypt_key(struct asymkey *akeyp, 
                         unsigned char *skey, unsigned long ssz, 
                         const unsigned char *cryptbuf, const unsigned long cryptsz) {
  int err;
  if ( ! akeyp->ready ) DIE("no key loaded");
  if ( (err=ecc_decrypt_key(cryptbuf, cryptsz, skey, &ssz, &akeyp->key)) != CRYPT_OK ) {
    DIET(err, "ecc_decrypt_key");
  }
}

