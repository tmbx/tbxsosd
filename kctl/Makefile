# Works for installing locally or creating a Debian package.

KCTL_LIB=kctllib/*.py
KCTL_CMDS=kctlcmd/*.py
KCTL=main.py

install-kctllib:
# Copy the kctl library.
	mkdir -p $(PREFIX)/share/python-support/kctllib/kctllib
	for i in $(KCTL_LIB); do \
		install -m644 $$i \
			$(PREFIX)/share/python-support/kctllib/kctllib;\
	done

install-kctllib-nodb:
# Copy the kctl nodb library.
	mkdir -p $(PREFIX)/share/python-support/kctllib-nodb/kctllib-nodb
	for i in $(KCTL_LIB); do \
		install -m644 $$i \
			$(PREFIX)/share/python-support/kctllib-nodb/kctllib-nodb;\
	done

install-kctl:
# Copy the kctl commands
	mkdir -p $(PREFIX)/share/python-support/kctlcmd/kctlcmd
	for i in $(KCTL_CMDS); do \
		install -m644 $$i \
			$(PREFIX)/share/python-support/kctlcmd/kctlcmd;\
	done

# Copy the 'binaries'
	mkdir -p $(PREFIX)/bin
	install -m755 main.py $(PREFIX)/bin/kctl
	install -m755 kctlimport $(PREFIX)/bin/kctlimport

install:
# Recall this makefile for all packages to install.
	make install-kctllib DEBIANDIR=$(DEBIANDIR) DEBIANPACKAGE=kctllib
	make install-kctllib-nodb DEBIANDIR=$(DEBIANDIR) DEBIANPACKAGE=kctllib-nodb
	make install-kctl DEBIANDIR=$(DEBIANDIR) DEBIANPACKAGE=kctl


