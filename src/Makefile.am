sbin_PROGRAMS = nacctd

man_MANS = nacctd.8 nacctpeering.8
nacctd_LDADD = @LIBOBJS@

nacctd_SOURCES = main.c \
	process.c \
	config.c \
	utils.c \
	capture.c \
	daemon.c \
	collect.c \
	mysql.c \
	oracle.c
EXTRA_DIST = naccttab.sample

INCLUDES = \
	-D$(OS) \
	-I$(top_srcdir) \
	-I$(includedir)

AM_FLAGS = $(cflags)

install-data-local:
	if [ ! -f $(DESTDIR)$(sysconfdir)/naccttab ]; then \
	 $(mkinstalldirs) $(DESTDIR)$(sysconfdir); \
	 $(INSTALL_DATA) $(srcdir)/naccttab.sample $(DESTDIR)$(sysconfdir)/naccttab; \
	 $(INSTALL_DATA) $(srcdir)/nacctpeering $(DESTDIR)$(sysconfdir)/nacctpeering; \
	fi

#this must be fixed: config dir in netacct.h
#install-data-local:
#	if [ ! -f /etc/naccttab ]; then \
#	 $(mkinstalldirs) $(DESTDIR)$(sysconfdir); \
#	 $(INSTALL_DATA) $(srcdir)/naccttab.sample /etc/naccttab; \
#	fi
			  

# nacctd_LDADD = $(OTHER)

oracle.c: oracle.pc
	ORACLE_HOME=@ORACLE_HOME@ \
	@PROC@

clean-compile:
	rm -f oracle.c
