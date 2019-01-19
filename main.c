/**
 ** main.c
 ** spor command line
 **/

/* TODO
 * - an optional outfd for a passthru hash? 
 * - use varargs in macros
 */

#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "spor.h"
#include "spor_ltc.h"
#include "util.h"

#define EXE "spor"
#define PWPROMPT  "Password: "
#define PWCONFIRM "Confirm Password: "

#define USAGE() \
fprintf(stderr, "Usage: " EXE " cmdstring\n"\
  "    [0,1,3-9]: set active file descriptor\n"\
  "    P,p: read password from (the terminal,active descriptor) and generate symmetric key\n"\
  "    i,o: set (input, output) to active file descriptor\n"\
  "    e,d: symmetric (encrypt,decrypt) input to output\n"\
  "    E,D: asymmetric (encrypt,decrypt) input to output\n"\
  "    g,f: asymmetric (sign,verify) input, signature to active descriptor\n"\
  "    b,v: asymmetric key type is (public,private)\n"\
  "    m,x: assymetric key (import from, export to) active descriptor\n"\
  "    k: generate new asymmetric key\n"\
  "spaces are ignored, active descriptor is reset to stdin/out when accessed.\n"\
  "passwords are are reset when used (i.e with e,d,vm, or vx).\n"\
  "PP forces password confirmation prompt\n"\
  "Examples:\n"\
  "    " EXE " 'k b3x PPvx 4g' 3>publickey >privatekey <file 4>file.sig\n"\
  "    " EXE " 'Pvm 3i 4f' <privatekey 3<file 4<file.sig\n"\
  "    " EXE " 'Pvm PPvx' <privatekey >privatekey.newpassphrase\n"\
  "     cat pwdfile | " EXE " 'p 3i 4o e' 3<clear 4>cipher\n"\
),exit(1)


/* global password buffers */
unsigned char pwbuf[BUFSZ], pwbuf2[BUFSZ];


void cleanup_atexit(void) {
  /* overwrite our stack memory with zeros 
   * size to burn is discovered experimentally
   * with stack_test.sh: increase the value until
   * the minimum stack size jumps
   * explicitly zero our password buffers
   */
  s0_teardown();
  zeromem(pwbuf, sizeof(pwbuf));
  zeromem(pwbuf2, sizeof(pwbuf2));
  burn_stack(1024*4);
}


/* manage input, output, active file descriptors */
#define GET(src, default) ((src<0) ? default : src)
#define NEXTIN() (infd=GET(nextfd, 0),(nextfd=-1, infd))
#define NEXTOUT() (outfd=GET(nextfd, 1), (nextfd=-1, outfd))
#define CLOSEIN() (close(infd),infd=0)
#define CLOSEOUT() (close(outfd), outfd=1)


int main(int argc, char **argv) {
  int infd = 0, outfd = 1, nextfd = -1, savfd;
  char *cmd;

  unsigned char *pwptr = NULL;
  char *pwprompt = PWPROMPT;
  unsigned pwsz = 0, pwsz2 = 0;
  
  struct asymkey akey;

  if (argc != 2 ) USAGE();
  cmd = argv[1];

  s0_setup();
  atexit(cleanup_atexit);
  
  for (int i=0; cmd[i]; i++) {
    switch ( cmd[i] ) {
    case ' ':              /* ignored for input readability */
      break; 

    case 'p':              /* get passphrase from a file descriptor */
      pwsz = read_or_die(NEXTIN(), pwbuf, sizeof(pwbuf), "reading passphrase"); 
      CLOSEIN();
      break;
    case 'P':              /* get a passphrase from the terminal */
      if ( pwsz ) {
        /* this is a confirmation read */
        memcpy(pwbuf2, pwbuf, pwsz);
        pwsz2 = pwsz;
        pwprompt = PWCONFIRM;
      }

      pwsz = readpass(pwprompt, pwbuf, sizeof(pwbuf));

      if ( pwsz2 ) {
        if ( pwsz != pwsz2 ) DIE("password mismatch");
        if ( memcmp(pwbuf, pwbuf2, pwsz) ) DIE("password mismatch"); 
      }
      zeromem(pwbuf2, pwsz2);
      break;

    case 'i':              /* (re)set active input descriptor */
        infd=NEXTIN();
        break;
    case 'o':              /*(re)set active output descriptor */
	outfd=NEXTOUT();
        break; 

    case 'e':              /* encrypt */
      s0_encrypt_stream(infd, outfd, pwbuf, pwsz);
      zeromem(pwbuf, pwsz);
      pwsz=0;
      CLOSEIN(); CLOSEOUT();
      break;
    case 'd':              /* decrypt */
      s0_decrypt_stream(infd, outfd, pwbuf, pwsz);
      zeromem(pwbuf, pwsz);
      pwsz=0;
      CLOSEIN(); CLOSEOUT();
      break;

    case 'E':
      s0_asym_encrypt_stream(&akey, infd, outfd);
      CLOSEIN(); CLOSEOUT();
      break;
    case 'D':
      s0_asym_decrypt_stream(&akey, infd, outfd);
      CLOSEIN(); CLOSEOUT();
      break;

    case 'g':              /* sign stream on infd, write sig to nextfd*/
      fprintf(stderr, "infd=%d, outfd=%d, nextfd=%d\n", infd, outfd, nextfd);
      s0_sign_stream(&akey, infd, NEXTOUT());
      CLOSEIN(); CLOSEOUT();
      break;
    case 'f':              /* verify stream on input with sig on next descriptor*/
      /* to keep the api consistent with other functions,
       * read the stream to be signed on infd
       * and force the caller to specify the fd of the sig
       */
      savfd = infd;
      s0_verify_stream(&akey, savfd, NEXTIN());
      CLOSEIN();
      break;

    case 'b':
      pwptr=NULL;
      break;
    case 'v':
      pwptr=pwbuf;
      break;

    case 'm':              /* mport asymmetric key */
      s0_import_key(&akey, NEXTIN(), pwptr, pwsz);
      if ( pwptr ) {
        zeromem(pwbuf, pwsz);
        pwsz=0;
      }
      CLOSEIN();
      break;
    case 'x':              /* xport asymmetric key */
      s0_export_key(&akey, NEXTOUT(), pwptr, pwsz);
      if ( pwptr ) {
        zeromem(pwbuf, pwsz);
        pwsz=0;
      }
      CLOSEOUT();
      break;
    case 'k':              /* generate asymmetric key */
      s0_create_key(&akey);
      break;


    case '0':
    case '1':
    /* don't smash stderr */
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
      nextfd = atoi(cmd+i);
      break;

    default:
      fprintf(stderr, "bad cmd: %c\n", cmd[i]);
      USAGE();
    }
  }  

  exit(0);
}


