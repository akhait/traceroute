CC = g++
CFLAGS = -std=c++11 -Wall -Wextra -pedantic
LOGIN = xkhait00
FILES = Makefile trace.h trace.cpp trace.1

all: 
	$(CC) $(CFLAGS) -o trace trace.h trace.cpp

clean:
	rm -f *.o *.out trace *.tgz *~

tar: clean
	tar -cvzf $(LOGIN).tgz $(FILES)
