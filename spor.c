/*
 * spor.c
 * stream interface and on-disk format
 */

#include <unistd.h>

#include "spor.h"
#include "pbkdf.h"
#include "util.h"

/***
 *** header format is:
 ***  bytes 0,1: magic number "s0"
 ***      2,3,4: format version 0
 ***          5: packet type: V=private key,B=public key,S=symmetric message,G=signature,A=asymmetric message
 *** followed by zero or more headers of the format:
 ***          n: header type: I=IV,L=salt,K=encrypted message key
 ***        n+1: header data length
 *** n+2,n+2+sz: header data
 ***/

/**
 ** Header access
 **/

void s0_read_magic(int infd, unsigned char type) {
  unsigned char hdr[4];
  int len;

  len = read_or_die(infd, hdr, sizeof(hdr), "reading header");
  if ( len < sizeof(hdr) ) DIED("short packet read fd", infd);

  if ( hdr[0] != 's' || hdr[1] != '0' ) DIEC2("bad magic", hdr[0], hdr[1]);
  if ( hdr[2] != SPOR_ONDISK_VERSION ) DIE("bad packet version");
  if ( hdr[3] != type ) DIEC("bad packet type", hdr[3]);
}

void s0_write_magic(int outfd, unsigned char type) {
  unsigned char hdr[4];
  hdr[0] = 's';
  hdr[1] = '0';
  hdr[2] = SPOR_ONDISK_VERSION;
  hdr[3] = type;
  if ( write_or_die(outfd, hdr, 4, "writing magic") < 4 ) DIE("short write in magic");
}

unsigned s0_read_header(int infd, unsigned char type, unsigned char *buf, unsigned sz) {
  unsigned char hdr[2];
  unsigned len;

  if ( read_or_die(infd, hdr, 2, "reading header") < 2 ) DIE("short read in header");
  if ( hdr[0] != type ) DIEC("bad header type", hdr[0]);
  if ( sz < hdr[1] ) DIEC2("buffer overflow", sz, hdr[1]);
  len = read_or_die(infd, buf, hdr[1], "reading header data");
  if ( len < hdr[1] ) DIE("short read in header data");   
  return len;
}

void s0_write_header(int outfd, unsigned char type, unsigned char *buf, unsigned char len) {
  unsigned char hdr[2];
  hdr[0] = type;
  hdr[1] = len;
  if ( write_or_die(outfd, hdr, 2, "writing header") < 2 ) DIE("short write in header");
  len = write_or_die(outfd, buf, len, "writing header data");
  if ( len != hdr[1] ) DIE("short write in header data");  
}

/**
 ** Asymmetric key management
 **/ 

void s0_create_key(struct asymkey *akeyp) {
  s0_asym_keygen(akeyp);
}

void s0_import_key(struct asymkey* akeyp, const int infd, 
                   unsigned char *pwbuf, const unsigned pwsz) {
  /* public/private are mixed because our caller doesn't know */
  unsigned char skey[KEYSZ_SYM];
  unsigned char iv[KEYSZ_SYM], salt[SALTSZ];
  unsigned char buf[BUFSZ];
  unsigned long len;

  if ( pwbuf ) {
    if ( ! pwsz ) DIE("no passphrase");
    s0_read_magic(infd, 'V');
    s0_read_header(infd, 'I', iv, sizeof(iv));
    s0_read_header(infd, 'L', salt, sizeof(salt));

    len = read_or_die(infd, buf, sizeof(buf), "reading key");

    s0_derive_key(skey, sizeof(skey), pwbuf, pwsz, salt, sizeof(salt));
    s0_cipher_init(skey, iv, sizeof(skey));
    s0_cipher_decrypt(buf, len);
    s0_cipher_done();
    zeromem(skey, sizeof(skey));

    s0_asym_import(buf, len, akeyp);

  } else {
    s0_read_magic(infd, 'B');
    len = read_or_die(infd, buf, sizeof(buf), "reading key");
    s0_asym_import(buf, len, akeyp);
  }   
}

void s0_export_key(struct asymkey *akeyp, const int outfd, 
                   unsigned char *pwbuf, const unsigned pwsz) {
  /* public/private are mixed because our caller doesn't know */
  unsigned char skey[KEYSZ_SYM];
  unsigned char iv[KEYSZ_SYM], salt[SALTSZ];
  unsigned char buf[BUFSZ];
  unsigned long sz = sizeof(buf);
 
  if ( pwbuf ) {
    if ( ! pwsz ) DIE("no passphrase");

    s0_prng_getbytes(iv, sizeof(iv));
    s0_prng_getbytes(salt, sizeof(salt));
   
    s0_write_magic(outfd, 'V');
    s0_write_header(outfd, 'I', iv, sizeof(iv));
    s0_write_header(outfd, 'L', salt, sizeof(salt));

    s0_derive_key(skey, sizeof(skey), pwbuf, pwsz, salt, sizeof(salt));
    s0_cipher_init(skey, iv, sizeof(skey));

    s0_asym_export(buf, &sz, 1, akeyp);

    s0_cipher_encrypt(buf, sz);
    s0_cipher_done();
    zeromem(skey, sizeof(skey));

  } else {
    s0_write_magic(outfd, 'B');
    s0_asym_export(buf, &sz, 0, akeyp);
  }

  write_or_die(outfd, buf, sz, "writing key");
}

/*
 * stream interfaces
 */

void s0_filter_stream(const int infd, const int outfd, 
                      void (filter)(unsigned char *, unsigned)) {
  unsigned char buf[BUFSZ];
  unsigned len;
  while ( (len=read(infd, buf, sizeof(buf))) > 0 ) {
    filter(buf, len);
    write_or_die(outfd, buf, len, "writing");
  }
  if ( len < 0 ) DIES("reading");
}

void s0_hash_stream(const int infd, unsigned char *hash, unsigned sz) {
  unsigned char buf[BUFSZ];
  int len;
  s0_hash_init();
  while ( (len=read(infd, buf, sizeof(buf))) > 0 ) {
    s0_hash_update(buf, len);
  }
  s0_hash_done(hash, sz);
}



void s0_encrypt_stream (const int infd, const int outfd, 
                        unsigned char *pwbuf, const unsigned pwsz) {
  /* read plaintext, write a header and ciphertext 
   */
  unsigned char skey[KEYSZ_SYM];
  unsigned char iv[sizeof(skey)];
  unsigned char salt[SALTSZ];

  if ( ! pwsz ) DIE("no passphrase");

  s0_prng_getbytes(iv, sizeof(iv));
  s0_prng_getbytes(salt, sizeof(salt));
  s0_derive_key(skey, sizeof(skey), pwbuf, pwsz, salt, sizeof(salt));

  s0_write_magic(outfd, 'S');
  s0_write_header(outfd, 'I', iv, sizeof(iv));
  s0_write_header(outfd, 'L', salt, sizeof(salt));

  s0_cipher_init(skey, iv, sizeof(skey));
  s0_filter_stream(infd, outfd, s0_cipher_encrypt);
  s0_cipher_done();

  zeromem(skey, sizeof(skey)); 
}

void s0_decrypt_stream(const int infd, const int outfd, 
                       unsigned char *pwbuf, const unsigned pwsz) {
  /* read header and ciphertext, write plaintext 
   */
  unsigned char skey[KEYSZ_SYM];
  unsigned char iv[sizeof(skey)], salt[SALTSZ];

  if ( ! pwsz ) DIE("no passphrase");

  s0_read_magic(infd, 'S');
  s0_read_header(infd, 'I', iv, sizeof(iv));
  s0_read_header(infd, 'L', salt, sizeof(salt));

  s0_derive_key(skey, sizeof(skey), pwbuf, pwsz, salt, sizeof(salt));

  s0_cipher_init(skey, iv, sizeof(skey));
  s0_filter_stream(infd, outfd, s0_cipher_decrypt);
  s0_cipher_done();

  zeromem(skey, sizeof(skey));
} 


void s0_sign_stream(struct asymkey *akeyp, const int infd, const int sigfd) {
  unsigned char hash[s0_hash_size()], sig[BUFSZ];
  unsigned long sigsz = sizeof(sig);
  s0_hash_stream(infd, hash, sizeof(hash));
  s0_asym_sign(akeyp, hash, sizeof(hash), sig, &sigsz);
  s0_write_magic(sigfd, 'G');
  write_or_die(sigfd, sig, sigsz, "writing signature");
}

void s0_verify_stream(struct asymkey *akeyp, const int infd, const int sigfd) {
  unsigned char hash[s0_hash_size()], sig[BUFSZ];
  unsigned long sigsz = sizeof(sig);
  unsigned success;

  s0_hash_stream(infd, hash, sizeof(hash));

  s0_read_magic(sigfd, 'G');
  sigsz = read_or_die(sigfd, sig, sigsz, "reading signature");

  success = s0_asym_verify(akeyp, hash, sizeof(hash), sig, sigsz);
  if ( ! success ) DIE("verification failed");
}


void s0_asym_encrypt_stream(struct asymkey *akeyp, const int infd, const int outfd) {
  unsigned char skey[KEYSZ_SYM];
  unsigned char iv[sizeof(skey)], skey_crypt[BUFSZ];
  unsigned long cryptlen = sizeof(skey_crypt);

  s0_prng_getbytes(skey, sizeof(skey));
  s0_prng_getbytes(iv, sizeof(iv));

  s0_asym_encrypt_key(akeyp, skey, sizeof(skey), skey_crypt, &cryptlen);

  s0_write_magic(outfd, 'A');
  s0_write_header(outfd, 'I', iv, sizeof(iv));
  s0_write_header(outfd, 'K', skey_crypt, cryptlen);
  
  s0_cipher_init(skey, iv, sizeof(skey));
  s0_filter_stream(infd, outfd, s0_cipher_encrypt);
  s0_cipher_done();

  zeromem(skey, sizeof(skey));
}

void s0_asym_decrypt_stream(struct asymkey *akeyp, const int infd, const int outfd) {
  unsigned char skey[KEYSZ_SYM];
  unsigned char skey_crypt[BUFSZ], iv[sizeof(skey)];
  unsigned long cryptlen;

  s0_read_magic(infd, 'A');
  s0_read_header(infd, 'I', iv, sizeof(iv));
  cryptlen = s0_read_header(infd, 'K', skey_crypt, sizeof(skey_crypt));

  s0_asym_decrypt_key(akeyp, skey, sizeof(skey), skey_crypt, cryptlen);

  s0_cipher_init(skey, iv, sizeof(skey));
  s0_filter_stream(infd, outfd, s0_cipher_decrypt);
  s0_cipher_done();

  zeromem(skey, sizeof(skey));
}


