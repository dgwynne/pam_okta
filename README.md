# Okta Authentication for Linux PAM

This provides a `pam_okta` PAM module (Pluggable Authentication Modules
module?) and a companion `oktad` daemon to support authenticating users
via Okta. Currently only authentication via the Device Authentication
API is implemented.

Instead of having a PAM module communicate with the Okta API directly,
this implementation connects to an `oktad` daemon over a Unix Domain
Socket and has the daemon handle the API communication on the modules
behalf. This has the following benefits:

- the module can be kept simple enough to only need libc and libpam as
  dependencies
  - this avoids potential problems with the module and the application
    using the module depending on or dlopening different versions of the
    same library
  - the code and side effects of the APIs are easier to reason about
    and clean up
- the module and therefore the authenticating process does not need
  access to the Okta client_id and client_secret
- the `oktad` daemon forks a handler per `pam_okta` authentication request
  - this isolates the authenticating process running `pam_okta` from
    the secrets needed to talk to the Okta API
  - each oktad handler process is isolated to mitigate the leaking of
    user information and credentials between authenticating processes
  - the oktad handler can simply exit if it encounters an error or
    unexpected condition without affecting other users
- the oktad process can (theoretically) be placed in a separate network
  namespace, or firewalled separately to the users on the system

## `oktad` configuration

Put a file like this in `/etc/okta/oktad.conf`:

```
# user "okta-daemon" # user the daemon drops prics to, defaults to _oktad
# socket "/path/to/uds/listener" # defaults to /var/run/okta/sock
host "something.okta.com"
client_id "XXX"
client_secret "YYY"
```

`/etc/okta` and `/etc/okta/oktad.conf` can be configured as only
accessible to the root user. The configuration file is opened by
`oktad` when it is running as root, and before it drops privileges to
the daemon user.

## `pam_okta` configuration

`pam_okta` supports the following arguments when used in a pam stack:

`socket=/path/to/uds/listener`, defaults to `/var/run/okta/sock`

`sshd=servicename` - `sshd` has special handling to report the
`SSH_CONNECTION` environment variable to `oktad`. This allows the
special sshd handling to be applied to a different service name for
testing purposes.

`mode=device` - only attempt a Device Authentication flow. This is
necessary at the moment while the code is rough, and because `oktad`
only supports Device Authentication currently.

## Building `oktad`

`oktad` needs the following dependencies on RPMish systems:

- `byacc`
- `libbsd-devel`
- `libcurl-devel`
- `json-c-devel`
- `jwt-devel`

```
$ cd oktad
$ meson build
# meson compile -C build
```

## Building `pam_okta`

`pam_okta` needs the following dependencies on RPMish systems:

- `pam-devel`

```
$ cd pam_okta
$ meson build
# meson compile -C build
```

## Installing

TODO

```
$ cd pam_okta
$ sudo install -m 0755 -o root -g root build/pam_okta.so /var/lib64/security
```

## Testing

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
$ sudo install -d -m 0700 -o root -g root /var/run/okta
$ cd oktad
$ sudo ./build/oktad -d
```

`pam-test-harness` from https://www.dtucker.net/patches/ is included in
the repo to help hack on this code.

```
$ cd pam-test-harness
$ meson build
$ meson compile -C build
$ sudo ./build/pam-test-harness -s oktatest
```

# Acknowledgements

Thanks to Damien Miller (djm) and Darren Tucker (dtucker) from the
OpenSSH and OpenBSD projects.

Thanks to Les Elliot (lje@uq.edu.au) for sanity checks and encouragement.
