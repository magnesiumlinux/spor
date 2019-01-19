/*
 * spor/pbkdf.h
 */
#ifndef SPOR_PBKDF_H
#define SPOR_PBKDF_H

void s0_derive_key (
  unsigned char *skey, 
  unsigned ssz, 
  unsigned char *pwbuf, 
  const unsigned pwsz, 
  unsigned char *salt, 
  const unsigned saltsz
);

#endif
