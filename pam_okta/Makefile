
all: pam_okta.so

pam_okta.so: pam_okta.o
	${LD} -x --shared -lpam -o $@ $^

pam_okta.o: pam_okta.c
	${CC} -fPIC -c -o $@ $^

.PHONY: install

install: pam_okta.so
	install -o root -g root -m 0755 pam_okta.so /usr/lib64/security/pam_okta.so
