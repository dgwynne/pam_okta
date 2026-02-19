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
static int		okta_handler(int, const struct okta_config *);
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
			return okta_handler(c, conf);
		default: /* parent */
			ldebug("%d ran okta_handler", pid);
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

	char			*form;
	size_t			 formlen;

	struct ucred		 cr;
	struct authn_field	 authn_fields[CTL_AUTHN_REQ_NFIELDS];
	struct response		*authorize;

	int64_t			 start_nsec;
};


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
request_exec(struct request *req)
{
	struct response *res;
	CURL *curl = req->curl;
	long status;

	req->form[req->formlen] = '\0';

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

#if 0
static int
okta_prompt(int c, const char *msg)
{
	size_t msglen = strlen(msg) + 1;
	struct ctl_authn_res res = {
		.hdr = { .type = CTL_T_AUTHN_RES, .hdrlen = sizeof(res) },
		.code = OKTA_CODE_SUCCESS,
		.msglen = msglen,
	};
	struct iovec iov[2] = {
		{ &res, sizeof(res) },
		{ (void *)msg, msglen },
	};
	ssize_t rv;

	rv = writev(c, iov, nitems(iov));
	if (rv == -1)
		lerrx(1, "prompt request");

	return (0);
}
#endif

static void
okta_handler_req(struct state *st, char *buf, size_t buflen)
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
		exit(0);

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

static const char *
okta_prompt(struct state *st, const char *snd, size_t sndlen,
    char *rcv, size_t rcvlen)
{
	struct ctl_authn_res *res = (struct ctl_authn_res *)rcv;
	struct iovec iov[2] = {
		{ res, sizeof(*res) },
		{ (void *)snd, sndlen },
	};
	ssize_t rv;
	size_t len;

	assert(rcvlen >= sizeof(*res));
	memset(res, 0, sizeof(*res));
	res->hdr.type = CTL_T_AUTHN_RES;
	res->hdr.hdrlen = sizeof(*res);
	res->code = OKTA_CODE_PROMPT;
	res->msglen = sndlen;

	rv = writev(st->fd, iov, nitems(iov));
	if (rv == -1)
		lerr(1, "prompt send");

	rv = read(st->fd, rcv, rcvlen);
	switch (rv) {
	case -1:
		lerr(1, "prompt recv");
		/* NOTREACHED */
	case 0:
		lerrx(1, "prompt recv disconnect");
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

static void
okta_reply(struct state *st, unsigned int code, const char *snd, size_t sndlen)
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
		lerr(1, "reply send");
}

static struct response *
okta_device_auth_poll(struct state *st)
{
	struct response *authorize = st->authorize;
	struct request *req;
	struct response *res;
	int64_t expires, now, last, diff, ivals, ival;
	const char *device_code;

	device_code = response_string(authorize, "device_code");

	expires = last = st->start_nsec;
	expires += response_int64(authorize, "expires_in") * NSECS;
	ival = (ivals = response_int64(authorize, "interval")) * NSECS;

	for (;;) {
		now = clock_read();
		if (now > expires)
			return (NULL);

		diff = now - last;
		if (diff < ival) {
			diff += NSECS - 1;
			diff /= NSECS;
			if (sleep(diff) != 0)
				continue;
		}

		last = now;

		req = request_init(st, "/oauth2/default/v1/token");

		request_add_data(req, "grant_type",
	    	    "urn:ietf:params:oauth:grant-type:device_code");
		request_add_data(req, "device_code", device_code);

		res = request_exec(req);
		if (res->status_code == 200)
			break;
		if (res->status_code != 400) {
			lerrx(1, "%s returned status code %u",
			    res->endpoint, res->status_code);
		}

		response_free(res);
	}

	return (res);
}

static void
okta_curl_init(struct state *st)
{
	char *client_id;
	char *client_secret;
	int rv;

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
}

static const char msg_auth_expired[] = "Authentication code expired";

static int
okta_handler(int c, const struct okta_config *conf)
{
	struct state _st = { .fd = c, .conf = conf };
	struct state *st = &_st;
	char buf[65536]; /* the authn fields live here */
	struct request *req;
	struct response *res;
	char *prompt;
	int rv;

	okta_handler_req(st, buf, sizeof(buf));

	if (authn_username(st) == NULL || authn_username_len(st) <= 1)
		lerrx(1, "no username in authn req from pid %d", st->cr.pid);

	linfo("authn request for user %s from pid %d",
	    authn_username(st), st->cr.pid);

	okta_curl_init(st);

	req = request_init(st, "/oauth2/default/v1/device/authorize");

	request_add_data(req, "scope", "openid profile offline_access");

	res = st->authorize = request_exec(req);
	if (res->status_code != 200) {
		/* XXX we should reply to pam */
		printf("oh no %s", res->data);
		lerr(1, "%s returned status code %u",
		    res->endpoint, res->status_code);
	}

	st->start_nsec = clock_read();

	rv = asprintf(&prompt, "Log in at %s, then press Enter to continue\n",
	    response_string(res, "verification_uri_complete"));
	if (rv == -1)
		lerrx(1, "authorize prompt printf");

	(void)okta_prompt(st, prompt, rv + 1, scratch, sizeof(scratch));
	free(prompt);

	res = okta_device_auth_poll(st);
	if (res == NULL) {
		lwarnx("%s", msg_auth_expired);
		okta_reply(st, OKTA_CODE_FAILURE,
		    msg_auth_expired, sizeof(msg_auth_expired));
		return (0);
	}

	jwt_t *jwt = NULL;

	if (jwt_decode(&jwt, response_string(res, "id_token"), NULL, 0) != 0)
		lerrx(1, "jwt decode failed");

	const char *username = jwt_get_grant(jwt, "preferred_username");
	if (username == NULL)
		lerrx(1, "jwt grant is missing the username");

	char *sep = strchr(username, '@');
	int cmp;
	if (sep == NULL)
		cmp = strcasecmp(username, authn_username(st));
	else {
		size_t len = sep - username;
		if (len != authn_username_len(st) - 1)
			cmp = -1;
		else
			cmp = strncasecmp(username, authn_username(st), len);
	}

	linfo("auth for pid %d user %s got %s from okta, returning %s",
	    st->cr.pid, authn_username(st), username,
	    cmp ? "failure" : "success");

	okta_reply(st, cmp ? OKTA_CODE_FAILURE : OKTA_CODE_SUCCESS, NULL, 0);

	return (0);
}
