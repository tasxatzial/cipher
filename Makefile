CFLAGS = -c -ansi -Wall -pedantic

crypto: crypto.o main.o util.o
	gcc main.o crypto.o util.o -o crypto

main.o: main.c crypto.h util.h
	gcc $(CFLAGS) main.c

crypto.o: crypto.c crypto.h util.h
	gcc $(CFLAGS) crypto.c

util.o: util.c util.h
	gcc $(CFLAGS) util.c

clean:
	rm -f *.o crypto
