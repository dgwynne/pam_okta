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

#include "compat.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>
#include <poll.h>
#include <pwd.h>
#include <grp.h>
#include <assert.h>
#include <errno.h>
#include <err.h>

#include <bsd/string.h> /* strlcpy */
#include <bsd/stdlib.h> /* getprogname */
#include <bsd/err.h>

#include "okta.h"
#include "log.h"

#include "protocol.h"

#define nitems(_a) (sizeof((_a)) / sizeof((_a)[0]))

static int		socket_open(const char *);
static int		pam_okta_handler(int, const struct okta_config *);
static void		sigchld(int);

__dead static void
usage(void)
{
	const char *progname = getprogname();

	fprintf(stderr, "usage: %s [-dn] [-f okta.conf]\n",
	    progname);

	exit(1);
}

int
main(int argc, char **argv)
{
	const char *conffile = OKTAD_CONFFILE;
	int confcheck = 0;
	int debug = 0;
	int ch;

	struct okta_config *conf;
	struct passwd *pw;
	int s;

	while ((ch = getopt(argc, argv, "df:n")) != -1) {
		switch (ch) {
		case 'd':
			debug = 1;
			break;
		case 'D':
			if (cmdline_symset(optarg) < 0) {
				errx(1, "could not parse macro definition %s",
				    optarg);
			}
			break;
		case 'f':
			conffile = optarg;
			break;
		case 'n':
			confcheck = 1;
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 0)
		usage();

	conf = parse_config(conffile);
	if (conf == NULL)
		exit(1);

	if (confcheck) {
		dump_config(conf);
		return (0);
	}

	if (geteuid() != 0)
		errx(1, "need root privileges");

	/* let's try and get going */
	pw = getpwnam(conf->user);
	if (pw == NULL)
		errx(1, "user \"%s\" not found", conf->user);

	s = socket_open(conf->sockname);

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		err(1, "unable to revoke privs");

	if (!debug && daemon(0, 0) == -1)
		err(1, "daemon");

	signal(SIGCHLD, sigchld);

	for (;;) {
		pid_t pid;

		int c = accept(s, NULL, NULL);
		if (c == -1) {
			lwarn("socket %s accept", conf->sockname);
			continue;
		}

		ldebug("got connection, forking");

		pid = fork();
		switch (pid) {
		case -1:
			lwarn("fork");
			break;
		case 0: /* child */
			close(s);
			return pam_okta_handler(c, conf);
		default: /* parent */
			ldebug("%d ran pam_okta handler", pid);
			close(c);
			break;
		}
	}

	return (0);
}

static int
socket_open(const char *sockname)
{
	struct sockaddr_un sun = {
		.sun_family = AF_UNIX,
	};
	mode_t oumask;
	int s;

	if (strlcpy(sun.sun_path, sockname, sizeof(sun.sun_path)) >=
            sizeof(sun.sun_path))
		errc(ENAMETOOLONG, 1, "socket");

	s = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (s == -1)
		err(1, "socket %s", sockname);

	/* try connect first? */

	if (unlink(sockname) == -1) {
		if (errno != ENOENT)
			err(1, "socket %s unlink", sockname);
	}

	oumask = umask(S_IXUSR|S_IXGRP|S_IWOTH|S_IROTH|S_IXOTH);
	if (bind(s, (struct sockaddr *)&sun, sizeof(sun)) == -1)
		err(1, "socket %s bind", sockname);
        umask(oumask);

	if (chmod(sockname, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP) == -1)
		err(1, "socket %s chmod", sockname);

	if (listen(s, 5) == -1)
		err(1, "socket %s listen", sockname);

	return (s);
}

static void
sigchld(int sig)
{
	pid_t pid;
	int wstat;

	do {
		pid = wait(&wstat);
	} while (pid != -1);
}

/*
 * okta authn request handler
 */

#include <curl/curl.h>
#include <json-c/json.h>
#include <jwt.h>
#include <ctype.h>

static const char msg_auth_expired[] = "Authentication code expired";
static const char msg_password_required[] = "Password required";
static const char msg_unsupported_mfa[] = "MFA challenge is not supported";

/* long strings are long */
#define OKTA_CHALLENGE_T_OOB "http://auth0.com/oauth/grant-type/mfa-oob"
#define OKTA_CHALLENGE_T_OTP "http://auth0.com/oauth/grant-type/mfa-otp"

static char scratch[65536];

#define NSECS 1000000000LL

struct authn_field {
	char		*str;
	size_t		 len;
};

struct state {
	int			 fd;
	const struct okta_config *
				 conf;
	char			*user_email;

	char			*form;
	size_t			 formlen;
	char			*forwarded_for;

	struct ucred		 cr;
	struct authn_field	 authn_fields[CTL_AUTHN_REQ_NFIELDS];
	unsigned int		 mode;
	struct response		*res_mfa;
	struct response		*res_poll;

	int64_t			 start_nsec;
};

__dead static void
pam_okta_disconnected(struct state *st)
{
	ldebug("pid %d disconnected, exiting", st->cr.pid);
	exit(0);
}

struct request {
	const char		*endpoint;
	CURL			*curl;
	struct curl_slist	*headers;
	char			*form;
	size_t			 formlen;

	char			*url;

	char			*data;
	size_t			 datalen;
};

struct response {
	const char		*endpoint;
	char			*data;
	size_t			 datalen;
	unsigned int		 status_code;
	struct json_object	*json;
};

static size_t
request_buffer(char *src, size_t size, size_t nmemb, void *arg)
{
	struct request *req = arg;
	size_t len = size * nmemb;
	size_t datalen = len + req->datalen;
	char *data;

	/* XXX check for overflow? */

	data = realloc(req->data, datalen + 1); /* add space for a nul */
	if (data == NULL)
		return (CURLE_WRITE_ERROR);

	req->data = data;
	memcpy(req->data + req->datalen, src, len);
	req->datalen = datalen;

	return (len);
}

static void
request_add_header(struct request *req, const char *h)
{
	req->headers = curl_slist_append(req->headers, h);
	if (req->headers == NULL)
		lerrx(1, "%s add header %s failed", req->endpoint, h);
}

static struct request *
request_init(struct state *st, const char *endpoint)
{
	struct request *req;
	CURL *curl;
	int rv;

	req = malloc(sizeof(*req));
	if (req == NULL)
		lerr(1, "%s request", endpoint);

	curl = curl_easy_init();
	if (curl == NULL)
		lerrx(1, "%s curl_easy_init failed", endpoint);

	rv = asprintf(&req->url, "https://%s%s", st->conf->host, endpoint);
	if (rv == -1)
		lerrx(1, "%s url init", endpoint);

	req->data = NULL;
	req->datalen = 0;

	curl_easy_setopt(curl, CURLOPT_URL, req->url);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, request_buffer);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, req);

	req->headers = NULL;
	request_add_header(req, "Accept: application/json");
	if (st->forwarded_for != NULL)
		request_add_header(req, st->forwarded_for);

	req->form = malloc(st->formlen + 1); /* + nul */
	if (req->form == NULL)
		lerr(1, "%s form init", endpoint);
	memcpy(req->form, st->form, st->formlen);
	req->formlen = st->formlen;

	req->endpoint = endpoint;
	req->curl = curl;

#if 0
	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
#endif

	return (req);
}

static void
request_add_data(struct request *req, const char *name, const char *data)
{
	char *key;
	size_t keylen;
	char *val;
	size_t vallen;
	size_t len;
	char *form;

	key = curl_easy_escape(NULL, name, strlen(name));
	if (key == NULL)
		lerrx(1, "%s add part %s name failed", req->endpoint, name);
	val = curl_easy_escape(NULL, data, strlen(data));
	if (val == NULL)
		lerrx(1, "%s add part %s data failed", req->endpoint, name);

	keylen = strlen(key);
	vallen = strlen(val);

	len = req->formlen;
	/* len + '&' + key + '=' + val + nul */
	form = realloc(req->form, len + 1 + keylen + 1 + vallen + 1);
	if (form == NULL)
		lerr(1, "%s add part %s", req->endpoint, name);

	form[len] = '&';
	len++;
	memcpy(form + len, key, keylen);
	len += keylen;
	form[len] = '=';
	len++;
	memcpy(form + len, val, vallen);
	len += vallen;

	req->form = form;
	req->formlen = len;

	free(key);
	free(val);
}

static struct response *
request_exec(struct request *req, int64_t timeoutns)
{
	struct response *res;
	CURL *curl = req->curl;
	long status;

	req->form[req->formlen] = '\0';

	if (timeoutns > 0) {
		long timeout = timeoutns / 1000000; /* nsec to msec */

		if (timeout < 500)
			timeout = 500;

		if (curl_easy_setopt(curl,
		    CURLOPT_TIMEOUT_MS, timeout) != CURLE_OK) {
			lerrx(1, "%s set timeout %ld ms failed",
			    req->endpoint, timeout);
		}
	}

	if (curl_easy_setopt(curl, CURLOPT_HTTPHEADER, req->headers)
	    != CURLE_OK)
		lerrx(1, "%s set headers failed", req->endpoint);
	if (curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req->form) != CURLE_OK)
		lerrx(1, "%s set form failed", req->endpoint);
	if (curl_easy_perform(curl) != CURLE_OK)
		lerrx(1, "%s request failed", req->endpoint);

	res = malloc(sizeof(*res));
	if (res == NULL)
		lerr(1, "%s response alloc", req->endpoint);

	if (curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status) !=
	    CURLE_OK)
		lerr(1, "%s response status", req->endpoint);

	req->data[req->datalen] = '\0';

	res->endpoint = req->endpoint;
	res->status_code = status;

	res->data = req->data;
	res->datalen = req->datalen;
	res->json = json_tokener_parse(res->data);
	if (res->json == NULL)
		lerrx(1, "unable to parse %s response", res->endpoint);

	curl_easy_cleanup(curl);
	free(req->url);
	free(req->form);
	curl_slist_free_all(req->headers);
	free(req);

	return (res);
}

static const char *
response_string(struct response *res, const char *key)
{
	struct json_object *v;

	if (json_object_object_get_ex(res->json, key, &v) == 0) {
		lerrx(1, "%s response doesn't contain %s",
		    res->endpoint, key);
	}

	if (!json_object_is_type(v, json_type_string)) {
		lerrx(1, "%s response %s isn't a string",
		    res->endpoint, key);
	}

	return json_object_get_string(v);
}

static int64_t
response_int64(struct response *res, const char *key)
{
	struct json_object *v;

	if (json_object_object_get_ex(res->json, key, &v) == 0) {
		lerrx(1, "%s response doesn't contain %s",
		    res->endpoint, key);
	}

	if (!json_object_is_type(v, json_type_int)) {
		lerrx(1, "%s response %s isn't an integer",
		    res->endpoint, key);
	}

	return json_object_get_int64(v);
}

static void
response_free(struct response *res)
{
	free(res->data);
	json_object_put(res->json);
	free(res);
}

#if 0
static int
printable(int ch)
{
	if (ch == '\0')
		return ('_');
	if (!isprint(ch))
		return ('~');

	return (ch);
}

static void
hexdump(const void *d, size_t datalen)
{
	const uint8_t *data = d;
	size_t i, j = 0;

	for (i = 0; i < datalen; i += j) {
		printf("%4zu: ", i);
		for (j = 0; j < 16 && i+j < datalen; j++)
			printf("%02x ", data[i + j]);
		while (j++ < 16)
			printf("   ");
		printf("|");
		for (j = 0; j < 16 && i+j < datalen; j++)
			putchar(printable(data[i + j]));
		printf("|\n");
	}
}
#endif

static const char * const authn_field_names[] = {
	[CTL_AUTHN_REQ_SERVICE]		= "service",
	[CTL_AUTHN_REQ_USERNAME]	= "username",
	[CTL_AUTHN_REQ_PASSWORD]	= "password",
	[CTL_AUTHN_REQ_RHOST]		= "rhost",
	[CTL_AUTHN_REQ_SSHENV]		= "sshenv",
};

static const char * const okta_code_names[] = {
	[OKTA_CODE_PROMPT]		= "prompt",
	[OKTA_CODE_SUCCESS]		= "success",
	[OKTA_CODE_FAILURE]		= "failure",
	[OKTA_CODE_DECLINE]		= "decline",
};

static inline const char *
authn_username(const struct state *st)
{
	return (st->authn_fields[CTL_AUTHN_REQ_USERNAME].str);
}

static inline size_t
authn_username_len(const struct state *st)
{
	return (st->authn_fields[CTL_AUTHN_REQ_USERNAME].len);
}

static inline const char *
authn_password(const struct state *st)
{
	return (st->authn_fields[CTL_AUTHN_REQ_PASSWORD].str);
}

static inline size_t
authn_password_len(const struct state *st)
{
	return (st->authn_fields[CTL_AUTHN_REQ_PASSWORD].len);
}

static int64_t
clock_read(void)
{
	int64_t nsec;

	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1)
		lerr(1, "clock gettime monotonic");

	nsec = ts.tv_sec * NSECS;
	nsec += ts.tv_nsec;

	return (nsec);
}

static int
is_cstring(const char *str, size_t len)
{
	size_t i;

	len--;
	if (str[len] != '\0')
		return (0);

	for (i = 0; i < len; i++) {
		if (!isprint(str[i]))
			return (0);
	}

	return (1);
}

static const char okta_scopes[] = "openid profile offline_access";

static void
pam_okta_handler_req(struct state *st, char *buf, size_t buflen)
{
	const struct ctl_authn_req *req = (const struct ctl_authn_req *)buf;
	socklen_t crlen = sizeof(st->cr);
	ssize_t rv;
	size_t len;
	char *ptr;
	size_t i;

	if (getsockopt(st->fd, SOL_SOCKET, SO_PEERCRED, &st->cr, &crlen) == -1)
		lerr(1, "getsockopt(SO_PEERCRED)");
	if (crlen < sizeof(st->cr))
		lerrx(1, "getsockopt(SO_PEERCRED) is short");

	ldebug("connection from pid %d uid %d gid %d",
	    st->cr.pid, st->cr.uid, st->cr.gid);

	rv = read(st->fd, buf, buflen);
	if (rv == -1)
		lerr(1, "authn req recv");
	if (rv == 0)
		pam_okta_disconnected(st);

	len = rv;

	if (len < sizeof(req->hdr))
		lerrx(1, "authn req ctl hdr is short, exiting");
	if (req->hdr.type != CTL_T_AUTHN_REQ)
		lerrx(1, "unexpected req type %u, exiting", req->hdr.type);
	if (req->hdr.hdrlen < sizeof(*req)) {
		lerrx(1, "authn req hdrlen %u is short (%zu), exiting",
		    req->hdr.hdrlen, sizeof(*req));
	}
	if (len < sizeof(*req))
		lerrx(1, "authn req hdr is short, exiting");
	if (req->version.major != 0) {
		lerrx(1, "authn req version %u.%u is unsupported, exiting",
		    req->version.major, req->version.minor);
	}

	switch (req->mode) {
	case OKTA_MODE_MFA_OOB:
	case OKTA_MODE_OOB:
	case OKTA_MODE_DEVICE_AUTH:
		st->mode = req->mode;
		break;
	default:
		lerrx(1, "unexpected mode %u, exiting", req->mode);
		/* NOTREACHED */
	}

	ptr = buf + req->hdr.hdrlen;
	len -= req->hdr.hdrlen;

	for (i = 0; i < nitems(st->authn_fields); i++) {
		struct authn_field *f = &st->authn_fields[i];

		f->len = req->fields[i];
		if (f->len == 0)
			f->str = NULL;
		else {
			if (f->len > len) {
				lerrx(1, "authn req %s is too long",
				    authn_field_names[i]);
			}

			f->str = ptr;
			if (!is_cstring(f->str, f->len)) {
				lerrx(1, "authn req %s is not a valid string",
				    authn_field_names[i]);
			}

			ptr += f->len;
			len -= f->len;
		}
	}
}

static void
pam_okta_reply(struct state *st, unsigned int code,
    const char *snd, size_t sndlen)
{
	struct ctl_authn_res res = {
		.hdr = { .type = CTL_T_AUTHN_RES, .hdrlen = sizeof(res) },
		.code = code,
		.msglen = sndlen,
	};
	struct iovec iov[2] = {
		{ &res, sizeof(res) },
		{ (void *)snd, sndlen },
	};
	ssize_t rv;

	rv = writev(st->fd, iov, nitems(iov));
	if (rv == -1)
		lerr(1, "%s send", okta_code_names[code]);
}

static const char *
pam_okta_prompt(struct state *st, const char *snd, size_t sndlen,
    char *rcv, size_t rcvlen)
{
	struct ctl_authn_res *res = (struct ctl_authn_res *)rcv;
	ssize_t rv;
	size_t len;

	pam_okta_reply(st, OKTA_CODE_PROMPT, snd, sndlen);

	rv = read(st->fd, rcv, rcvlen);
	switch (rv) {
	case -1:
		lerr(1, "prompt recv");
		/* NOTREACHED */
	case 0:
		pam_okta_disconnected(st);
		/* NOTREACHED */
	default:
		break;
	}

	len = rv;
	if (len < sizeof(res->hdr))
		lerrx(1, "prompt recv short hdr");
	if (res->hdr.type != CTL_T_AUTHN_RES)
		lerrx(1, "prompt recv unexpected res type %u", res->hdr.type);
	if (res->hdr.hdrlen < sizeof(*res))
		lerrx(1, "prompt recv short hdrlen");
	if (len < sizeof(*res))
		lerrx(1, "prompt recv res hdr");

	len -= res->hdr.hdrlen;

	if (len < res->msglen)
		lerrx(1, "prompt recv short msg");

	len = res->msglen;
	if (len == 0)
		lerrx(1, "prompt recv got NULL");

	rcv += res->hdr.hdrlen;
	if (!is_cstring(rcv, len))
		lerrx(1, "prompt recv got invalid c string");

	return (rcv);
}

int
fdsleep(struct state *st, int64_t nsecs)
{
	struct pollfd pfd = {
		.fd = st->fd,
		.events = POLLRDHUP,
	};
	struct timespec ts;
	int rv;

	ts.tv_sec = nsecs / NSECS;
	ts.tv_nsec = nsecs % NSECS;

	rv = ppoll(&pfd, 1, &ts, NULL);
	switch (rv) {
	case -1:
		if (errno == EINTR)
			return (-1);

		lerr(1, "%s ppoll", __func__);
		/* NOTREACHED */
	case 0:
		/* timeout expired */
		return (0);
	}

	if (pfd.revents & POLLHUP) {
		pam_okta_disconnected(st);
		/* NOTREACHED */
	}

	lerrx(1, "unexpected ppoll state: fd %d, events 0x%x, revents 0x%x",
	    pfd.fd, pfd.events, pfd.revents);
}

struct okta_token_poller {
	const char *code_field;
	const char *grant_type;
	const char *scope;
};

static const struct okta_token_poller okta_mfa_oob_poller = {
	.code_field = "oob_code",
	.grant_type = "http://auth0.com/oauth/grant-type/mfa-oob",
	.scope = okta_scopes,
};

static const struct okta_token_poller okta_oob_poller = {
	.code_field = "oob_code",
	.grant_type = "urn:okta:params:oauth:grant-type:oob",
	.scope = okta_scopes,
};

static const struct okta_token_poller okta_device_poller = {
	.code_field = "device_code",
	.grant_type = "urn:ietf:params:oauth:grant-type:device_code",
};

static void
okta_token_done(struct state *st, struct response *res)
{
	jwt_t *jwt = NULL;
	const char *username;
	int cmp;

	if (res == NULL) {
		lwarnx("%s", msg_auth_expired);
		pam_okta_reply(st, OKTA_CODE_FAILURE,
		    msg_auth_expired, sizeof(msg_auth_expired));
		return;
	}
	if (res->status_code != 200) { /* 401 or 403 */
		linfo("auth for pid %d user %s got %u %s: %s",
		    st->cr.pid, authn_username(st), res->status_code,
		    response_string(res, "error"),
		    response_string(res, "error_description"));
		pam_okta_reply(st, OKTA_CODE_FAILURE, NULL, 0);
		return;
	}

	if (jwt_decode(&jwt, response_string(res, "id_token"), NULL, 0) != 0)
		lerrx(1, "jwt decode failed");

	username = jwt_get_grant(jwt, "preferred_username");
	if (username == NULL)
		lerrx(1, "jwt grant is missing the username");

	cmp = strcasecmp(username, st->user_email);

	linfo("auth for pid %d user %s got %s from okta, returning %s",
	    st->cr.pid, authn_username(st), username,
	    cmp ? "failure" : "success");

	pam_okta_reply(st, cmp ? OKTA_CODE_FAILURE : OKTA_CODE_SUCCESS,
	    NULL, 0);
}

static struct response *
okta_token_poll(struct state *st, const struct okta_token_poller *p)
{
	struct response *res_mfa = st->res_mfa;
	struct response *res_poll = st->res_poll;
	struct request *req;
	struct response *res;
	int64_t expires, now, last, diff, ival, tmo;
	const char *code;

	code = response_string(res_poll, p->code_field);

	expires = last = st->start_nsec;
	expires += response_int64(res_poll, "expires_in") * NSECS;
	ival = response_int64(res_poll, "interval") * NSECS;
	tmo = ival - (NSECS / 2);

	do {
		now = clock_read();
		if (now > expires)
			return (NULL);

		diff = now - last;
		if (diff < ival) {
			diff += arc4random_uniform(NSECS / 2);
			if (fdsleep(st, diff) != 0)
				continue;
		}

		last = now;

		req = request_init(st, "/oauth2/v1/token");

		if (p->scope != NULL)
			request_add_data(req, "scope", p->scope);
		request_add_data(req, "grant_type", p->grant_type);
		request_add_data(req, p->code_field, code);
		if (res_mfa != NULL) {
			request_add_data(req, "mfa_token",
			    response_string(res_mfa, "mfa_token"));
		}

		res = request_exec(req, tmo);
		switch (res->status_code) {
		case 200:
		case 401:
		case 403:
			break;
		case 429:
			lwarnx("%s status %u: %s",
			    res->endpoint, res->status_code, res->data);
			response_free(res);
			res = NULL;
			break;
		case 400:
			if (strcmp(response_string(res, "error"),
			    "slow_down") == 0) {
				ival += NSECS / 10;
				response_free(res);
				res = NULL;
				break;
			}
			if (strcmp(response_string(res, "error"),
			    "authorization_pending") == 0) {
				response_free(res);
				res = NULL;
				break;
			}
			/* FALLTHROUGH */
		default:
			lerrx(1, "%s status %u: %s",
			    res->endpoint, res->status_code, res->data);
			/* NOTREACHED */
		}
	} while (res == NULL);

	return (res);
}

static void
okta_curl_init(struct state *st)
{
	char *client_id;
	char *client_secret;
	int rv;

	rv = asprintf(&st->user_email, "%s@%s",
	    authn_username(st), st->conf->domain);
	if (rv == -1)
		lerrx(1, "user_email init failed");

	curl_global_init(CURL_GLOBAL_ALL);

	client_id = curl_easy_escape(NULL,
	    st->conf->client_id, strlen(st->conf->client_id));
	if (client_id == NULL)
		lerrx(1, "client_id form init failed");

	client_secret = curl_easy_escape(NULL,
	    st->conf->client_secret, strlen(st->conf->client_secret));
	if (client_id == NULL)
		lerrx(1, "client_secret form init failed");

	rv = asprintf(&st->form, "client_id=%s&client_secret=%s",
	    client_id, client_secret);
	if (rv == -1)
		lerrx(1, "form init failed");

	st->formlen = rv;

	free(client_id);
	free(client_secret);

	if (st->authn_fields[CTL_AUTHN_REQ_SSHENV].len > 0) {
		struct addrinfo hints = {
			.ai_family = AF_UNSPEC,
			.ai_socktype = SOCK_STREAM,
			.ai_protocol = IPPROTO_TCP,
			.ai_flags = AI_NUMERICHOST,
		};
		struct addrinfo *res0;
		const char *sshenv;
		char *sep;
		char host[NI_MAXHOST];
		size_t len;

		sshenv = st->authn_fields[CTL_AUTHN_REQ_SSHENV].str;
		sep = strchr(sshenv, ' ');
		if (sep == NULL)
			lerrx(1, "malformed SSH_CONNECTION");
		len = sep - sshenv;
		if (len >= sizeof(host))
			lerrx(1, "malformed SSH_CONNECTION, long host");
		memcpy(host, sshenv, len);
		host[len] = '\0';

		rv = getaddrinfo(host, NULL, &hints, &res0);
		if (rv != 0) {
			lerrx(1, "SSH_CONNECTION remote host: %s",
			    gai_strerror(rv));
		}
		freeaddrinfo(res0);

		rv = asprintf(&st->forwarded_for,
		    "X-Forwarded-For: %s", host);
		if (rv == -1)
			lerrx(1, "X-Forwarded-For init");
	}
}


static void
okta_oob_challenge(struct state *st, const struct okta_token_poller *p)
{
	struct response *res_poll = st->res_poll;
	struct response *res;
	char *prompt;
	const char *binding_method;
	int rv;

	binding_method = response_string(res_poll, "binding_method");
	if (strcmp(binding_method, "none") == 0) {
		rv = asprintf(&prompt,
		    "Push notification sent, press Enter to continue");
	} else if (strcmp(binding_method, "transfer") == 0) {
		rv = asprintf(&prompt,
		    "Push code %s sent, press Enter to continue",
		    response_string(res_poll, "binding_code"));
	} else {
		lwarnx("unsupported binding method %s", binding_method);
		pam_okta_reply(st, OKTA_CODE_FAILURE,
		    msg_unsupported_mfa, sizeof(msg_unsupported_mfa));
		return;
	}

	if (rv == -1)
		lerrx(1, "oob auth prompt");

	(void)pam_okta_prompt(st, prompt, rv + 1, scratch, sizeof(scratch));
	free(prompt);

	/* re-using res */
	res = okta_token_poll(st, p);
	okta_token_done(st, res);
}

static void
okta_mfa_oob_auth(struct state *st)
{
	struct request *req;
	struct response *res;
	const char *challenge_type;

	if (authn_password(st) == NULL) {
		lwarnx("password required for mfa-oob authentication");
		pam_okta_reply(st, OKTA_CODE_FAILURE,
		    msg_password_required, sizeof(msg_password_required));
		return;
	}

	req = request_init(st, "/oauth2/v1/token");

	request_add_data(req, "scope", okta_scopes);
	request_add_data(req, "grant_type", "password");
	request_add_data(req, "username", authn_username(st));
	request_add_data(req, "password", authn_password(st));

	res = st->res_mfa = request_exec(req, 0);
	switch (res->status_code) {
	case 200:
		/* password auth succeeded */
		okta_token_done(st, res);
		return;
	case 400:
		if (strcmp(response_string(res, "error"),
		    "invalid_grant") == 0) {
			const char *msg;

			msg = response_string(res, "error_description");
			pam_okta_reply(st, OKTA_CODE_FAILURE,
			    msg, strlen(msg) + 1);
			return;
		}
		goto res_error;
	case 403:
		if (strcmp(response_string(res, "error"),
		    "mfa_required") == 0)
			break;
		goto res_error;
	default:
		goto res_error;
	}

	req = request_init(st, "/oauth2/v1/challenge");

	request_add_data(req, "mfa_token", response_string(res, "mfa_token"));
	request_add_data(req, "channel_hint", "push");
	request_add_data(req, "challenge_types_supported",
	    OKTA_CHALLENGE_T_OOB
#ifdef notyet
	    " " OKTA_CHALLENGE_T_OTP);
#endif
	);

	res = st->res_poll = request_exec(req, 0);
	if (st->res_poll->status_code != 200)
		goto res_error;

	st->start_nsec = clock_read();

	challenge_type = response_string(st->res_poll, "challenge_type");
	if (strcmp(challenge_type, OKTA_CHALLENGE_T_OOB) == 0) {
		okta_oob_challenge(st, &okta_mfa_oob_poller);
		return;
	}

	lwarnx("unsupported challenge type %s", challenge_type);
	pam_okta_reply(st, OKTA_CODE_FAILURE,
	    msg_unsupported_mfa, sizeof(msg_unsupported_mfa));
	return;

res_error:
	lerrx(1, "%s status code %u %s: %s",
	    res->endpoint, res->status_code,
	    response_string(res, "error"),
	    response_string(res, "error_description"));
}

static void
okta_oob_auth(struct state *st)
{
	struct request *req;
	struct response *res;

	req = request_init(st, "/oauth2/v1/primary-authenticate");

	request_add_data(req, "login_hint", authn_username(st));
	request_add_data(req, "challenge_hint", okta_oob_poller.grant_type);
	request_add_data(req, "channel_hint", "push");

	res = st->res_poll = request_exec(req, 0);
	switch (res->status_code) {
	case 200:
		/* oob has been initiated */
		break;
	default:
		goto res_error;
	}

	st->start_nsec = clock_read();

	okta_oob_challenge(st, &okta_oob_poller);
	return;

res_error:
	lerrx(1, "%s status code %u %s: %s",
	    res->endpoint, res->status_code,
	    response_string(res, "error"),
	    response_string(res, "error_description"));
}

static void
okta_device_auth(struct state *st)
{
	struct request *req;
	struct response *res;
	char *prompt;
	int rv;

	req = request_init(st, "/oauth2/v1/device/authorize");

	request_add_data(req, "scope", okta_scopes);

	res = st->res_poll = request_exec(req, 0);
	switch (res->status_code) {
	case 200:
		break;
	case 400:
	case 401:
		linfo("%s returned %u %s: %s", res->endpoint, res->status_code,
		    response_string(res, "error"),
		    response_string(res, "error_description"));
		/* NOTREACHED */
	case 429:
	default:
		lerr(1, "%s returned %u: %s", res->endpoint,
		    res->status_code, res->data);
		/* NOTREACHED */
	}

	st->start_nsec = clock_read();

	rv = asprintf(&prompt, "Log in at %s, then press Enter to continue",
	    response_string(res, "verification_uri_complete"));
	if (rv == -1)
		lerrx(1, "authorize prompt printf");

	(void)pam_okta_prompt(st, prompt, rv + 1, scratch, sizeof(scratch));
	free(prompt);

	res = okta_token_poll(st, &okta_device_poller);
	okta_token_done(st, res);
}

static int
pam_okta_handler(int c, const struct okta_config *conf)
{
	struct state _st = { .fd = c, .conf = conf };
	struct state *st = &_st;
	char buf[65536]; /* the authn fields live here */

	pam_okta_handler_req(st, buf, sizeof(buf));

	if (authn_username(st) == NULL || authn_username_len(st) <= 1)
		lerrx(1, "no username in authn req from pid %d", st->cr.pid);

	linfo("authn request for user %s from pid %d",
	    authn_username(st), st->cr.pid);

	okta_curl_init(st);

	switch (st->mode) {
	case OKTA_MODE_MFA_OOB:
		okta_mfa_oob_auth(st);
		break;
	case OKTA_MODE_OOB:
		okta_oob_auth(st);
		break;
	case OKTA_MODE_DEVICE_AUTH:
		okta_device_auth(st);
		break;
	default:
		lwarnx("%s: unexpected st->mode %u", __func__, st->mode);
		abort();
		/* NOTREACHED */
	}

	return (0);
}
