# Okta Authentication for Linux PAM

This provides a `pam_okta` PAM module (Pluggable Authentication Modules
module?) and a companion `pam_oktad` daemon to support authenticating
users via Okta using the Device Authorization and Direct Authentication
flows.

Instead of having a PAM module communicate with the Okta API directly,
this implementation connects to an `pam_oktad` daemon over a Unix Domain
Socket and has the daemon handle the API communication on the modules
behalf. `pam_oktad` runs persistently waiting for connections to the Unix
Domain Socket it is listening on, and forks a handler for each connection
to it.

This has the following benefits:

- the module can be kept simple enough to only need libc and libpam as
  dependencies
  - this avoids potential problems with the module and the application
    using the module depending on or dlopening different versions of the
    same library
  - the code and side effects of the APIs are easier to reason about
    and clean up
- the module and therefore the authenticating process does not need
  access to the Okta client_id and client_secret
- the `pam_oktad` daemon forks a handler per `pam_okta` authentication
  request
  - this isolates the authenticating process running `pam_okta` from
    the secrets needed to talk to the Okta API
  - each handler process is isolated to mitigate against the leaking of
    user information and credentials between authenticating processes
  - a handler can exit if it encounters an error or unexpected
    condition without affecting other users
- the daemon can (theoretically) be placed in a separate network
  namespace, or firewalled separately to the users on the system

## `pam_oktad` configuration

Put a file like this in `/etc/okta/pam_oktad.conf`:

```
# user "okta-daemon" # defaults to _pam_oktad, user the daemon runs as
# socket "/path/to/uds/listener" # defaults to /var/run/pam_okta/sock
host "something.okta.com"
domain "example.com"
# authorization server id "default" # optional, unused if not set
client_id "XXX"
client_secret "YYY"
```

The domain configuration is added to the authenticating username to
create an "email" style identifier for the user.

`/etc/okta` and `/etc/okta/pam_oktad.conf` can be configured as only
accessible to the root user. The configuration file is opened by
`pam_oktad` when it is running as root, and before it drops privileges
to the daemon user.

## `pam_okta` configuration

`pam_okta` supports the following arguments when used in a pam stack:

`socket=/path/to/uds/listener`, defaults to `/var/run/pam_okta/sock`

`mode=mfa-oob` directly authenticates users using their password and
possibly out-of-band (OOB) as a second factor. This is the default mode.
It follows the [Direct Authentication using the Okta Verify Push (MFA)](https://developer.okta.com/docs/guides/configure-direct-auth-grants/dmfaoobov/main/) flow.

`mode=oob` only attempts out-of-band (OOB) authentication using Okta
Verify Push.
It follows the [Direct Authentication using the Okta Verify Push (primary factor)](https://developer.okta.com/docs/guides/configure-direct-auth-grants/coobov/main/) flow.

`mode=device` uses the [Device Authentication](https://developer.okta.com/docs/guides/device-authorization-grant/main/) flow to authenticate users.

`sshd=servicename`: `sshd` reports the connection information to PAM
modules via the `SSH_CONNECTION` environment variable. `pam_okta` and
`pam_oktad` use this to report the SSH client IP to the Okta API if the
`PAM_SERVICE` is `sshd`. This setting specifies an alternate service
name for enabling this special handling for testing purposes. In is
generally not necessary to configure this in production.

## Using `pam_okta` and `pam_oktad`

- Install dependencies

  `pam_okta` only uses libc and libpam, which are almost certainly already
  installed.
  `pam_oktad` has the following runtime dependencies:
  - `libbsd`
  - `libcurl`
  - `jansson`
  - `libjwt`

- create /var/run/pam_okta 

```
$ sudo install -d -o root -g root -m 0700 /var/run/pam_okta
```

- run the daemon

```
# sudo pam_oktad
```

- systemd unit and selinux stuff (TODO)
- add pam_okta to your pam stack

### OpenSSH

`sshd` needs to be configured via `sshd_config` to use PAM with keyboard
interactive authentication enabled. This allows allows the user to be be
prompted for MFA by `pam_okta`. The relevant documentation is:

```
       UsePAM  Enables  the  Pluggable Authentication Module interface.  If set
               to   yes   this   will   enable   PAM    authentication    using
               KbdInteractiveAuthentication and PasswordAuthentication in addi‐
               tion  to  PAM  account and session module processing for all au‐
               thentication types.

               Because PAM keyboard-interactive authentication  usually  serves
               an  equivalent  role to password authentication, you should dis‐
               able          either          PasswordAuthentication          or
               KbdInteractiveAuthentication.

               If  UsePAM  is enabled, you will not be able to run sshd(8) as a
               non-root user.  The default is no.

       KbdInteractiveAuthentication
               Specifies whether to allow keyboard-interactive  authentication.
               All authentication styles from login.conf(5) are supported.  The
               default is yes.  The argument to this keyword must be yes or no.
               ChallengeResponseAuthentication is a deprecated alias for this.

       PAMServiceName
               Specifies the service name  used  for  Pluggable  Authentication
               Modules (PAM) authentication, authorisation and session controls
               when UsePAM is enabled.  The default is sshd.
```

The suggested configuration is:

```
UsePAM yes
KbdInteractiveAuthentication Yes
```

### SELinux

TODO

selinux blocks sshd from talking to /var/run/pam_okta/sock by default.

## Building

`pam_okta` needs the following dependencies on RPMish systems:

- `pam-devel`

`pam_oktad` needs the following dependencies on RPMish systems:

- `byacc`
- `libbsd-devel`
- `libcurl-devel`
- `jansson-devel`
- `jwt-devel`

```
$ meson setup build
$ meson compile -C build
```

## Installing

TODO

```
$ sudo install -m 0755 -o root -g root build/pam_okta/pam_okta.so /lib64/security
```

## Testing

`pam-test-harness` from https://www.dtucker.net/patches/ is included in
the repo to help hack on this code.

```
$ cd pam-test-harness
$ meson setup build
$ meson compile -C build
$ sudo ./build/pam-test-harness -s oktatest
```

```
$ cat /etc/pam.d/oktatest 
#%PAM-1.0
#auth       substack     password-auth
auth        required     pam_env.so
#auth        required    pam_faildelay.so delay=2000000
auth        sufficient   pam_okta.so sshd=oktatest mode=device
auth        required     pam_deny.so

auth       include      postlogin
account    required     pam_sepermit.so
account    required     pam_nologin.so
account    include      password-auth
password   include      password-auth
# pam_selinux.so close should be the first session rule
session    required     pam_selinux.so close
session    required     pam_loginuid.so
# pam_selinux.so open should only be followed by sessions to be executed in the user context
session    required     pam_selinux.so open env_params
session    required     pam_namespace.so
session    optional     pam_keyinit.so force revoke
session    optional     pam_motd.so
session    include      password-auth
session    include      postlogin
```

```
$ sudo install -d -m 0700 -o root -g root /var/run/pam_okta
$ # groupadd _pam_oktad
$ # useradd _pam_oktad
$ sudo ./build/pam_oktad/pam_oktad -
```

# Todo

- use "direct" auth as a fallback option for "mfa-oob" and "oob" auth

# Acknowledgements

Thanks to Damien Miller (djm) and Darren Tucker (dtucker) from the
OpenSSH and OpenBSD projects.

Thanks to Les Elliot (lje@uq.edu.au) for sanity checks and encouragement.
