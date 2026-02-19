
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

#define CTL_T_AUTHN_REQ		0
#define CTL_T_AUTHN_RES		1

struct ctl_header {
	unsigned int		type;
	unsigned int		hdrlen;
};

enum ctl_auth_req_fields {
	CTL_AUTHN_REQ_SERVICE,
	CTL_AUTHN_REQ_USERNAME,
	CTL_AUTHN_REQ_PASSWORD,
	CTL_AUTHN_REQ_RHOST,
	CTL_AUTHN_REQ_SSHENV,

	CTL_AUTHN_REQ_NFIELDS
};

struct ctl_authn_req {
	struct ctl_header	hdr;
	struct {
		uint16_t		major;
		uint16_t		minor;
	}			version;

	unsigned int		mode;
#define OKTA_MODE_DIRECT_AUTH		0
#define OKTA_MODE_DEVICE_AUTH		1

	unsigned int		fields[CTL_AUTHN_REQ_NFIELDS];
};

struct ctl_authn_res {
	struct ctl_header	hdr;

	unsigned int		code;
#define OKTA_CODE_PROMPT		0
#define OKTA_CODE_SUCCESS		1
#define OKTA_CODE_FAILURE		2
#define OKTA_CODE_DECLINE		3
	unsigned int		msglen;
};
