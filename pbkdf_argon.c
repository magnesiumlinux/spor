#include <stdio.h>

#include <argon2.h>

#include "spor.h"
#include "pbkdf.h"


#define DIEA(err, msg) fprintf(stderr, "died %s: %s\n", msg, argon2_error_message(err)),exit(1)


void s0_derive_key (unsigned char *skey, unsigned ssz, 
                    unsigned char *passphrase, const unsigned pwlen, 
                    unsigned char *salt, const unsigned saltlen) {
  int err;

  argon2_context context = {
    skey, ssz,
    passphrase, pwlen,
    salt, saltlen,
    NULL, 0,        /* secret data */
    NULL, 0,        /* associated data */
    ARGON_TCOST, ARGON_MCOST, 
    ARGON_PARALLEL, ARGON_PARALLEL,
    ARGON2_VERSION_NUMBER,
    NULL, NULL,     /* memory de/allocation */
    ARGON2_DEFAULT_FLAGS
  };

  if ( (err=argon2d_ctx(&context)) != ARGON2_OK ) DIEA(err, "hashing passphrase"); 
}

