# spor

## A minimalist cryptographic stream format and scripting tool

spor attempts to expose a complete set of cryptographic primitives in 
the smallest self-contained executable possible.  That's currently 1.8MB 
on my system, and includes hashing, symmetic encryption, and public key 
encryption and signing.

### building

You will need the tomcrypt library (libtom.net) built against either (or 
both) the tomsfastmath or gmp math libraries.  They seem to work equally 
well -- if you want to use gmp, change the MATH #define in spor.h from 
'tfm_desc' to 'gmp_desc'.

You will need the argon2 password-based key derivation function library 
(https://github.com/P-H-C/phc-winner-argon2)

Compilation with gcc and GNU make works for me, it will probably work 
for you, too, question mark.

### moving parts

spor reads and writes data from numbered file descriptors, such as can 
be opened using the redirection operators ('<', '>', '|') in common 
shell environments.

The following pieces of data are stored internally:

 * the active file descriptor: if set, this will be used as the input or 
output descriptor for the next command that requires one;

 * the input file descriptor: the descriptor to be used for reading. It 
is closed and reset to the default input descriptor 0 after us
use;

 * the output file descriptor: the descriptor to be used for writing. It 
is closed and reset to the default output descriptor 1 after use;

 * the active password: will be reset and overwritten after use;

 * an asymmetric keypair: will remain in memory until the end 
of program execution or until another keypair is loaded. 


### running

spor accepts a single argument, the commandstring.  Each character of 
the commandstring is read and executed in order. invalid characters in 
the string will cause execution to abort with an error.

Spaces in the commandstring are ignored, and are useful for maintaining 
commandstring readability.

Digits set the active file descriptor. Only single-digit file 
descriptors are currently supported.  Trying to use descriptor 2 
(standard error) will cause spor to abort.

'P' opens the TTY and interactively prompts for a password and stores it 
in memory. 'PP' causes a confirmation prompt -- spor aborts if the 
passwords don't match.

'p' reads a passphrase from the input file descriptor and stores it in 
memory.

'i' and 'o' respectively set the (i)nput and (o)utput descriptor, to the 
active descriptor.

'e' and 'd' respectively symmetrically (e)ncrypt and (d)ecrypt data from 
the input descriptor to the output descriptor, using the passphrase 
stored in memory.

'E' and 'D' do the same using the asymmetrical key stored in memory.

'g' and 'f' respectively si(g)n and veri(f)y the data from the input 
descriptor.  The signature is read or written to the active descriptor. 
N.B. verification is the only spor command where two pieces of data are 
read; accordingly, you *must* specify the active descriptor explicitly.

'b' and 'v' set the key type to, respectively, pu(b)lic or pri(v)ate.  
This should appear before 'm' or 'x' (below) in your commandstring.  The 
default if unset is public.

'm' i(m)ports a public or private key from the input descriptor.

'x' e(x)ports a public or private key to the output descriptor.

'k' generates a new asymmetric(public,private) key pair and stores it in 
memory.


### Examples

####  spor 'k b3x PPvx 4g' 3>publickey >privatekey <file 4>file.sig

Generate a keypair, and sign a file with the new key:

 * 'k' creates a new asymmetic key pair and stores it in memory.
 * 'b3x' exports the public key to output descriptor 3
 * 'PP' prompts for (the same) passphrase twice, directly on the active 
TTY, and stores it to memory
 * 'vx' encrypts the private key with the stored passphrase and 
exports it to the (default) output descriptor 1.
 * '4g' reads 'file' from the (default) input descriptor 0 and 
writes the signature to active descriptor 4.


#### spor 'Pvm 3i 4f' <privatekey 3<file 4<file.sig

Sign a file with an existing private key:

 * 'Pvm' prompts for a passphrase on the TTY, and imports a private key 
on (default) output descriptor 1. 

 * '3i' sets the input descriptor to 3

 * '4f' verifies the data read from the input descriptor with the 
signature read from active descriptor 4.


#### spor 'Pvm PPvx' <privatekey >privatekey.newpassphrase

Change the passphrase on a private key:

 * 'Pvm' prompts for a passphrase on the TTY, and imports a priVate key 
read from (default) input descriptor 0
 * 'PPvx' prompts for (and confirms) another Passphrase on the TTY and 
exports the private key to (default) output descriptor 1


####  cat pwdfile | spor 'p 3i 4o e' 3<clear 4>cipher

Encrypt a file with a passphrase read from a file
 * 'p' reads a passphrase from (default) input descriptor 0
 * '3i' sets the input descriptor for the next command to 3
 * '4o' sets the output descriptor for the next command to 4
 * 'e' applies symmetric encryption, reading from the input 
descriptor and writing to the outputdescriptor


## stream format

The stream format is described in this comment in spor.c:

```
/***
 *** header format is:
 ***  bytes 0,1: magic number "s0"
 ***      2,3,4: format version 0
 ***          5: packet type: V=private key,B=public key,S=symmetric message,
                 G=signature,A=asymmetric message
 *** followed by zero or more headers of the format:
 ***          n: header type: I=IV,L=salt,K=encrypted message key
 ***        n+1: header data length
 *** n,n+1...sz: header data
 ***/
```

followed by the raw data stream. 

(more to come)


## bugs/todo/open questions

 * implement hashing!

 * are the on-disk formats actually compatible across multiple 
architectures and operating systems?

 * multiple-digit file descriptors should be straightforward to 
implement, but the use cases aren't compelling for the added complexity?

 * signals are not caught, which means that our cleanup code (mostly 
memory zeroing) is not run in those cases

 * how effective is our memory zeroing code, anyway?

 * are symmetrical signatures interesting or useful?

 * asymmetric keys are currently serialized with tomcrypt's internal 
code.  should we/can we do this ourselves?

 * is there value in implementing an authenticated encryption mode?

