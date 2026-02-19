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

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include "protocol.h"

#define nitems(_a) (sizeof((_a)) / sizeof((_a)[0]))

struct state {
	pam_handle_t	*pamh;
	unsigned int	 flags;
#define CFG_F_DEBUG		(1 << 0)
#define CFG_F_NO_WARN		(1 << 1)
	unsigned int	 first_pass;
#define CFG_FIRST_PASS_UNSET	0
#define CFG_FIRST_PASS_USE	1
#define CFG_FIRST_PASS_TRY	2
	unsigned int	 mode;

	const char	*sockname;
	const char	*sshd; /* which service provides SSH_CONNECTION env */

	const char	*service;
	size_t		 servicelen;
	const char	*user;
	size_t		 userlen;
	const char	*pass;
	size_t		 passlen;
	const char	*rhost;
	size_t		 rhostlen;
	const char	*sshenv;
	size_t		 sshenvlen;
};

static const char sockopt[] = "socket=";
#define SOCKOPTLEN (sizeof(sockopt) - 1)
static const char sshdopt[] = "sshd=";
#define SSHDOPTLEN (sizeof(sshdopt) - 1)

static int
parse_args(struct state *st, int argc, const char **argv)
{
	int i;

	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "debug") == 0) {
			st->flags |= CFG_F_DEBUG;
		} else if (strcmp(argv[i], "no_warn") == 0) {
			st->flags |= CFG_F_NO_WARN;
		} else if (strcmp(argv[i], "use_first_pass") == 0) {
			st->first_pass = CFG_FIRST_PASS_USE;
		} else if (strcmp(argv[i], "try_first_pass") == 0) {
			st->first_pass = CFG_FIRST_PASS_TRY;
		} else if (strcmp(argv[i], "mode=direct") == 0) {
			st->mode = OKTA_MODE_DIRECT_AUTH;
		} else if (strcmp(argv[i], "mode=device") == 0) {
			st->mode = OKTA_MODE_DEVICE_AUTH;
		} else if (strncmp(argv[i], sockopt, SOCKOPTLEN) == 0) {
			st->sockname = argv[i] + SOCKOPTLEN;
		} else if (strncmp(argv[i], sshdopt, SSHDOPTLEN) == 0) {
			st->sshd = argv[i] + SSHDOPTLEN;
		} else {
			pam_syslog(st->pamh, LOG_ERR,
			    "unexpected argument %s", argv[i]);
			return (-1);
		}
	}

	return (0);
}

static int
okta_authn_password(pam_handle_t *pamh, struct state *st)
{
	int rv;

	if (st->first_pass == CFG_FIRST_PASS_UNSET) {
		char *pass;

		rv = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF,
		    &pass, "Password: ");
		if (rv != PAM_SUCCESS) {
			pam_syslog(pamh, LOG_ERR,
			    "password prompt: %s", pam_strerror(pamh, rv));
			return (rv);
		}
		if (pass == NULL) {
			rv = PAM_CONV_ERR;
			pam_syslog(pamh, LOG_ERR,
			    "password prompt: %s", pam_strerror(pamh, rv));
			return (rv);
		}

		rv = pam_set_item(pamh, PAM_AUTHTOK, pass);
		explicit_bzero(pass, strlen(pass));
		free(pass);
		if (rv != PAM_SUCCESS) {
			pam_syslog(pamh, LOG_ERR,
			    "set authtok: %s", pam_strerror(pamh, rv));
			return (rv);
		}
	}

	rv = pam_get_authtok(pamh, PAM_AUTHTOK, &st->pass, NULL);
	if (rv != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_ERR,
		    "get authtok: %s", pam_strerror(pamh, rv));
		return (rv);
	}
	if (st->pass == NULL) {
		rv = PAM_BAD_ITEM;
		pam_syslog(pamh, LOG_ERR,
		    "get authtok: %s", pam_strerror(pamh, rv));
		return (rv);
	}

	st->passlen = strlen(st->pass) + 1;

	return (PAM_SUCCESS);
}

static int
okta_authn_prepare(struct state *st)
{
	pam_handle_t *pamh = st->pamh;
	const void *item;
	int rv;

	rv = pam_get_item(pamh, PAM_SERVICE, &item);
	if (rv != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_ERR,
		    "PAM_SERVICE: %s", pam_strerror(pamh, rv));
		return (rv);
	}
	if (item == NULL) {
		pam_syslog(pamh, LOG_ERR, "PAM_SERVICE is not set");
		return (PAM_SERVICE_ERR);
	}
	st->service = item;
	st->servicelen = strlen(st->service) + 1;

	rv = pam_get_user(pamh, &st->user, NULL);
	if (rv != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_ERR,
		    "pam_get_user: %s", pam_strerror(pamh, rv));
		return (rv);
	}
	st->userlen = strlen(st->user) + 1;

	if (st->mode == OKTA_MODE_DIRECT_AUTH) {
		rv = okta_authn_password(pamh, st);
		if (rv != PAM_SUCCESS)
			return (rv);
	}

	rv = pam_get_item(pamh, PAM_RHOST, &item);
	if (rv != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_ERR,
		    "PAM_RHOST: %s", pam_strerror(pamh, rv));
		return (rv);
	}
	if (item != NULL) {
		st->rhost = item;
		st->rhostlen = strlen(st->rhost) + 1;
	}

	if (strcmp(st->sshd, st->service) == 0) {
		st->sshenv = pam_getenv(pamh, "SSH_CONNECTION");
		if (st->sshenv != NULL)
			st->sshenvlen = strlen(st->sshenv) + 1;
	}

	return (PAM_SUCCESS);
}

static int
okta_connect(struct state *st)
{
	struct sockaddr_un sun = {
		.sun_family = AF_UNIX,
	};
	size_t socknamelen;
	int s;

	/* i miss strlcpy */
	socknamelen = strlen(st->sockname);
	if (socknamelen >= sizeof(sun.sun_path)) {
		pam_syslog(st->pamh, LOG_ERR,
		    "okta socket name is too long");
		return (-1);
	}

	s = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (s == -1) {
		pam_syslog(st->pamh, LOG_ERR,
		    "socket: %s", strerror(errno));
		return (-1);
	}

	memcpy(sun.sun_path, st->sockname, socknamelen);
	sun.sun_path[socknamelen] = '\0';

	if (connect(s, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
		pam_syslog(st->pamh, LOG_ERR,
		    "socket %s connect: %s", st->sockname, strerror(errno));
		close(s);
		return (-1);
	}

	return (s);
}

static int
okta_authn(struct state *st, int s)
{
	struct ctl_authn_req r = {
		.hdr = { .type = CTL_T_AUTHN_REQ, .hdrlen = sizeof(r) },
		.version = { .major = 0, .minor = 0 },
		.mode = st->mode,

		.fields = {
			[CTL_AUTHN_REQ_SERVICE] = st->servicelen,
			[CTL_AUTHN_REQ_USERNAME] = st->userlen,
			[CTL_AUTHN_REQ_PASSWORD] = st->passlen,
			[CTL_AUTHN_REQ_RHOST] = st->rhostlen,
			[CTL_AUTHN_REQ_SSHENV] = st->sshenvlen,
		},
	};
	struct iovec iov[] = {
		{ &r, sizeof(r) },
		{ (void *)st->service, st->servicelen },
		{ (void *)st->user, st->userlen },
		{ (void *)st->pass, st->passlen },
		{ (void *)st->rhost, st->rhostlen },
		{ (void *)st->sshenv, st->sshenvlen },
	};
	ssize_t rv;

	rv = writev(s, iov, nitems(iov));
	if (rv == -1) {
		pam_syslog(st->pamh, LOG_ERR, "socket %s write authn: %s",
		    st->sockname, strerror(errno));
		return (PAM_AUTHINFO_UNAVAIL);
	}

	return (PAM_SUCCESS);
}

static int
okta_respond(pam_handle_t *pamh, struct state *st, int s,
    char *str, size_t len)
{
	struct ctl_authn_res res = {
		.hdr = { .type = CTL_T_AUTHN_RES, .hdrlen = sizeof(res) },
		.code = OKTA_CODE_PROMPT,
		.msglen = len,
	};
	struct iovec iov[2] = {
		{ &res, sizeof(res) },
		{ str, len },
	};
	ssize_t rv;

	rv = writev(s, iov, nitems(iov));
	if (rv == -1) {
		pam_syslog(st->pamh, LOG_ERR, "socket %s write res: %s",
		    st->sockname, strerror(errno));
		return (PAM_SERVICE_ERR);
	}

	return (PAM_INCOMPLETE); /* loop */
}

static int
okta_prompt(pam_handle_t *pamh, struct state *st, int s, const char *prompt)
{
	char *p = NULL;
	int rv;
	size_t len;

	rv = pam_prompt(pamh, PAM_PROMPT_ECHO_ON, &p, "%s", prompt);
	if (rv != PAM_SUCCESS)
		return (rv);
	if (p == NULL)
		return (PAM_SERVICE_ERR);

	len = strlen(p) + 1;

	rv = okta_respond(pamh, st, s, p, len);

	explicit_bzero(p, len);
	free(p);

	return (rv);
}

static int
okta_loop(pam_handle_t *pamh, struct state *st, int s)
{
	char buf[65536];
	char *str = NULL;
	struct ctl_authn_res *res = (struct ctl_authn_res *)buf;
	ssize_t rv;
	size_t len;

	rv = read(s, buf, sizeof(buf));
	switch (rv) {
	case -1:
		pam_syslog(pamh, LOG_ERR,
		    "socket %s read: %s", st->sockname, strerror(errno));
		return (PAM_SERVICE_ERR);
	case 0:
		pam_syslog(pamh, LOG_DEBUG,
		    "socket %s disconnected", st->sockname);
		return (PAM_SERVICE_ERR);
	default:
		break;
	}

	len = rv;
	if (len < sizeof(res->hdr)) {
		pam_syslog(pamh, LOG_ERR,
		    "socket %s short hdr read (%zu < %zu bytes)", st->sockname,
		    len, sizeof(res->hdr));
		return (PAM_SERVICE_ERR);
	}
	if (res->hdr.type != CTL_T_AUTHN_RES) {
		pam_syslog(pamh, LOG_ERR,
		    "socket %s unexpected res type %u", st->sockname,
		    res->hdr.type);
		return (PAM_SERVICE_ERR);
	}
	if (res->hdr.hdrlen < sizeof(*res)) {
		pam_syslog(pamh, LOG_ERR,
		    "socket %s short res hdrlen", st->sockname);
		return (PAM_SERVICE_ERR);
	}
	if (len < sizeof(*res)) {
		pam_syslog(pamh, LOG_ERR,
		    "socket %s short res hdr", st->sockname);
		return (PAM_SERVICE_ERR);
	}

	len -= res->hdr.hdrlen;

	if (len < res->msglen) {
		pam_syslog(pamh, LOG_ERR,
		    "socket %s short res msg (%u < %zu)",
		    st->sockname, res->msglen, len);
		return (PAM_SERVICE_ERR);
	}
	len = res->msglen;
	if (len > 0) {
		str = buf + res->hdr.hdrlen;
		len--; /* remove nul byte accounting */
		if (str[len] != '\0') {
			pam_syslog(pamh, LOG_ERR,
			    "socket %s bad msg string", st->sockname);
			return (PAM_SERVICE_ERR);
		}

		pam_syslog(pamh, LOG_DEBUG,
		    "socket %s msg %s", st->sockname, str);
	}

	switch (res->code) {
	case OKTA_CODE_PROMPT:
		if (str == NULL || len < 1) {
			pam_syslog(pamh, LOG_ERR,
			    "socket %s prompt without msg", st->sockname);
			return (PAM_SERVICE_ERR);
		}
		break;
	case OKTA_CODE_SUCCESS:
		pam_syslog(pamh, LOG_DEBUG,
		    "socket %s success for user %s",
		    st->sockname, st->user);
		return (PAM_SUCCESS);
	case OKTA_CODE_DECLINE:
		pam_syslog(pamh, LOG_DEBUG,
		    "socket %s declined user %s",
		    st->sockname, st->user);
		return (PAM_USER_UNKNOWN);
	case OKTA_CODE_FAILURE:
		pam_syslog(pamh, LOG_DEBUG,
		    "socket %s auth failure for user %s",
		    st->sockname, st->user);
		return (PAM_AUTH_ERR);
	default:
		abort();
	}

	return (okta_prompt(pamh, st, s, str));
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	pam_syslog(pamh, LOG_DEBUG, "%s", __func__);

	return (PAM_USER_UNKNOWN);
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	struct state _st = { /* c is annoying */
		.pamh = pamh,
		.sockname = "/var/run/okta/sock",
		.sshd = "sshd",
		.mode = OKTA_MODE_DIRECT_AUTH,
	};
	struct state *st = &_st;
	int rv;
	int s;

	pam_syslog(pamh, LOG_DEBUG, "%s", __func__);

	if (parse_args(st, argc, argv) == -1)
		return (PAM_SERVICE_ERR);

	rv = okta_authn_prepare(st);
	if (rv != PAM_SUCCESS)
		return (rv);

	pam_syslog(pamh, LOG_DEBUG, "%s[%u]", __func__, __LINE__);

	s = okta_connect(st);
	pam_syslog(pamh, LOG_DEBUG, "%s[%u]", __func__, __LINE__);
	if (s == -1)
		return (PAM_SERVICE_ERR);

	pam_syslog(pamh, LOG_DEBUG, "%s[%u]", __func__, __LINE__);
	rv = okta_authn(st, s);
	pam_syslog(pamh, LOG_DEBUG, "%s[%u]", __func__, __LINE__);

	do {
		rv = okta_loop(pamh, st, s);
	} while (rv == PAM_INCOMPLETE);

	close(s);

	return (rv);
}
