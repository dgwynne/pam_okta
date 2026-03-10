/* */

/*
 * Copyright (c) 2026 The University of Queensland
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define OKTAD_CONFFILE	"/etc/okta/pam_oktad.conf"

#define OKTAD_USERNAME	"_pam_oktad"

enum okta_cred_type {
	OKTA_CRED_UNSET,
	OKTA_CRED_CLIENT_SECRET,
	OKTA_CRED_PRIVATE_KEY_JWT,
	OKTA_CRED_CLIENT_SECRET_JWT,
};

struct okta_config {
	char		*user;
	char		*sockname;

	char		*host;
	char		*authserver;
	char		*domain;
	char		*client_id;
	char		*cred;
	enum okta_cred_type
			 cred_type;

	struct {
		char			*kid;
		jwt_alg_t		 alg;
		unsigned char		*key;
		size_t			 len;
	}		 jwt;
};

int	cmdline_symset(const char *);
struct okta_config *
	parse_config(const char *);
void	clear_config(struct okta_config *);
void	dump_config(const struct okta_config *);

int	jwt_pkey_alg(const char *);
