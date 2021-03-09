/*
 * spor_ltc.h
 * definitions for building spor against libtomcrypt
 */

#ifndef SPOR_LTC_H
#define SPOR_LTC_H

#include <tomcrypt.h>

struct asymkey {
    unsigned char ready;
    ecc_key key;
};


#endif
