

LIBS=-ltomcrypt -ltfm -lgmp -largon2
CFLAGS=-DTFM_DESC -DGMP_DESC -Wno-cpp -O2
CC=gcc -Wall

spor:main.o spor.o spor_ltc.o pbkdf_argon.o util.o
	$(CC) $(CFLAGS) -static -o spor $^  $(LIBS)

main.o: main.c spor.h util.h
spor.o: spor.c pbkdf.h spor.h util.h 
spor_ltc.o: spor_ltc.c spor.h util.h 
pbkdf_argon.o: pbkdf_argon.c pbkdf.h util.h
util.o: util.c util.h

clean: .PHONY
	rm -rf spor *.o testfiles

test: spor
	./test.sh

stacktest: spor
	./test_stack.sh

.PHONY:
