all: oktad

oktad: oktad.o log.o parse.o
	$(CC) -lbsd -lcurl -ljson-c -ljwt -o $@ $^

