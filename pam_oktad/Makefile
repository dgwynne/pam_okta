all: pam_oktad

pam_oktad: oktad.o log.o parse.o
	$(CC) -lbsd -lcurl -ljansson -ljwt -o $@ $^
