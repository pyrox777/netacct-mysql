# Network Traffic Accounting Daemon

The application is used for accounting of the network traffic passing through
your router/gateway. It is based on the libpcap library and functions as a
userspace daemon. Options for dividing the network traffic into 4 categories:

- international
- peering
- direct
- local

The traffic accounts are saved in a database, and for the time being MySQL is
(and Oracle might be) supported. As libpcap is used for gathering the network
data the application runs (for the moment) on the following operating systems:

- Linux
- FreeBSD
- OpenBSD
- Solaris

Please be aware of the fact that only the Linux sources are built and used at
the moment, but you are very welcome to submit feedback or merge requests to
support other operating systems.

For more detailed information regarding a particular OS, please read the
[FAQ](FAQ) file and the original [README](README) files.

## Dependencies

To download this project, use: `git clone https://github.com/pyrox777/netacct-mysql.git`

To build this project, the following is needed:

* `gcc`
* `libpcap` - libpcap-dev
* `mysqlclient-dev` (up to Debian 8) or `libmariadb-dev libmariadb-dev-compat` (from Debian 9)
* `make`

On a Debian-based system, try using: `apt install gcc libpcap-dev libmariadb-dev libmariadb-dev-compat make`

## Build

Inside the project's root directory:

* `./configure`
* `make`

If you would like to install nacctd on the local system, use `make install`. This copies the `nacctd` binary to `/usr/local/sbin`, the configuration files `nacctab.sample` to `/usr/local/etc/nacttab` and `nacctpeering` to `/usr/local/etc/nacctpeering`. The man pages `nacctd` and `nacctpeering` are copied as well.

## Configure

See [README](README) for the meantime.