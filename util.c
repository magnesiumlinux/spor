
/*
 * spor/util.c
 */

#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "util.h"

int readpass(char *prompt, unsigned char *buf, unsigned sz) {
  int fd, len;
  struct termios term, term_old;

  if ( (fd=open("/dev/tty", O_RDWR)) < 0 ) DIES("opening TTY");
  if ( ! isatty(fd) ) DIES("not a TTY");
  if ( tcgetattr(fd, &term_old) ) DIES("reading TTY settings");

  memcpy(&term, &term_old, sizeof(struct termios));
  term.c_lflag = (term.c_lflag & ~ECHO) | ECHONL;
  if ( tcsetattr(fd, TCSANOW, &term) < 0 ) DIES("writing TTY settings");

  if ( write(fd, prompt, strlen(prompt)) < 0 ) DIES("prompting for password");

  if ( (len=read(fd, buf, sz)) < 0 ) DIES("reading password");

  if ( tcsetattr(fd, TCSANOW, &term_old) < 0 ) DIES("resetting TTY");
  close(fd);

  while ( buf[len-1]=='\r' || buf[len-1]=='\n') {
    buf[--len] = '\0';
  }

  return len;
}


int read_or_die(int fd, unsigned char *buf, unsigned sz, char *msg) {
  int len;
  if ( (len=read(fd, buf, sz)) < 0 ) DIES(msg);
  return len;

}

int write_or_die (int fd, unsigned char *buf, unsigned sz, char *msg) {
  int len;
  if ( (len=write(fd, buf, sz)) < 0 ) DIES(msg); 
  return len;
}


/**
 **  burn_stack and zeromem, from libtomcrypt by Tom St Denis
 **/

/* 
   Burn some stack memory
   @param len amount of stack to burn in bytes
*/
void burn_stack(unsigned long len) {
   volatile unsigned char buf[32];
   zeromem(buf, sizeof(buf));
   if (len > (unsigned long)sizeof(buf))
      burn_stack(len - sizeof(buf));
}

/**
   Zero a block of memory
   @param out    The destination of the area to zero
   @param outlen The length of the area to zero (octets)
*/
void zeromem(volatile void *out, size_t outlen){
   volatile char *mem = out;
   while (outlen-- > 0) {
      *mem++ = '\0';
   }
}


