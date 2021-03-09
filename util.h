/*
 * spor/util.h
 */
#ifndef SPOR_UTIL_H
#define SPOR_UTIL_H

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FOO(msg) fprintf(stderr, "%s\n", msg);

#define DIE(msg) fprintf(stderr, "died %s\n", msg),exit(2)
#define DIEC(msg, a) fprintf(stderr, "died %s: %c\n", msg, a),exit(2);
#define DIEC2(msg, a,b) fprintf(stderr, "died %s: %c,%c\n", msg, a, b),exit(2);
#define DIED(msg, a) fprintf(stderr, "died %s: %d\n", msg, a),exit(2);
#define DIES(msg) fprintf(stderr, "died %s: %s\n", msg, strerror(errno)),exit(2)
#define DIES2(msg,a) fprintf(stderr, "died %s %s: %s\n", msg, a, strerror(errno)), exit(2)


int readpass(char *prompt, unsigned char *buf, unsigned sz);
int read_or_die(int fd, unsigned char *buf, unsigned sz, char *msg);
int write_or_die (int fd, unsigned char *buf, unsigned sz, char *msg);

void burn_stack(unsigned long len);
void zeromem(volatile void *out, size_t outlen);

#endif
