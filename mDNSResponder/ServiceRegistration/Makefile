BUILDDIR = build
OBJDIR = objects

ifndef os
  SYSTEM := $(shell uname -s)
  ifeq ($(SYSTEM), Darwin)
    os=x
  else ifeq ($(SYSTEM), Linux)
    os_id := $(shell sed -n -e 's/^ID=//p' < /etc/os-release)
    ifeq ($(os_id), raspbian)
      os=raspbian
    else
      os=linux
    endif
  endif
endif

ifdef INSTBASE
  INSTALL_PREFIX=$(INSTBASE)
else
  INSTALL_PREFIX=$(DESTDIR)/usr
endif

CP?=/bin/cp

ifeq ($(os),x)
SRPCFLAGS = -O0 -g -Wall -Werror -DSTANDALONE -I../mDNSCore -I/usr/local/include -I. -I../mDNSShared -I../DSO -MMD -MF .depfile-${notdir $<} -DUSE_KQUEUE -DHAVE_SOCKADDR_DL
SRPLDOPTS = -lmbedcrypto -lmbedtls -lmbedx509
else ifeq ($(os), linux)
SRPCFLAGS = -DMDNS_UDS_SERVERPATH=\"/var/run/mdnsd\" -O0 -g -Wall -Werror -DSTANDALONE -I../mDNSCore -I/usr/local/include -I. -I../mDNSShared -I../DSO -MMD -MF .depfile-${notdir $<} -DNOT_HAVE_SA_LEN -DUSE_SELECT -DUSE_INOTIFY
SRPLDOPTS = -lmbedcrypto -lmbedtls -lmbedx509
else ifeq ($(os), linux-uclibc)
SRPCFLAGS = -DMDNS_UDS_SERVERPATH=\"/var/run/mdnsd\" -O0 -g -Wall -Werror -DSTANDALONE -I../mDNSCore -I/usr/local/include -I. -I../mDNSShared -I../DSO -MMD -MF .depfile-${notdir $<} -DNOT_HAVE_SA_LEN -DUSE_SELECT -DLINUX_GETENTROPY
SRPLDOPTS = -lmbedcrypto -lmbedtls -lmbedx509
else ifeq ($(os), raspbian)
SRPCFLAGS = -DMDNS_UDS_SERVERPATH=\"/var/run/mdnsd\" -O0 -g -Wall -Werror -DSTANDALONE -I../mDNSCore -I/usr/local/include -I. -I../mDNSShared -I../DSO -MMD -MF .depfile-${notdir $<} -DNOT_HAVE_SA_LEN -DUSE_SELECT -DLINUX_GETENTROPY -DGENKEY_PROGRAM=$(GENKEY) -DCERTWRITE_PROGRAM=$(CERTWRITE)
SRPLDOPTS = /usr/local/lib/libmbedtls.a /usr/local/lib/libmbedx509.a /usr/local/lib/libmbedcrypto.a
endif

all:	setup $(BUILDDIR)/srp-simple $(BUILDDIR)/keydump $(BUILDDIR)/dnssd-proxy # $(BUILDDIR)/dnssd-relay

install: all
	$(CP) $(BUILDDIR)/srp-simple $(INSTALL_PREFIX)/sbin
	$(CP) $(BUILDDIR)/srp-gw $(INSTALL_PREFIX)/sbin
	$(CP) $(BUILDDIR)/dnssd-proxy $(INSTALL_PREFIX)/sbin
	$(CP) $(BUILDDIR)/keydump $(INSTALL_PREFIX)/bin

# 'setup' sets up the build directory structure the way we want
setup:
	@if test ! -d $(OBJDIR)   ; then mkdir -p $(OBJDIR)   ; fi
	@if test ! -d $(BUILDDIR) ; then mkdir -p $(BUILDDIR) ; fi

# clean removes targets and objects
clean:
	@if test -d $(OBJDIR)   ; then rm -r $(OBJDIR)   ; fi
	@if test -d $(BUILDDIR) ; then rm -r $(BUILDDIR) ; fi

HMACOBJS     = $(OBJDIR)/hmac-mbedtls.o
SIGNOBJS     = $(OBJDIR)/sign-mbedtls.o 
SIMPLEOBJS   = $(OBJDIR)/towire.o $(SIGNOBJS)
DSOOBJS      = $(OBJDIR)/dso.o
MDNSOBJS     = $(OBJDIR)/dnssd_clientstub.o $(OBJDIR)/dnssd_ipc.o
VERIFYOBJS   = $(OBJDIR)/verify-mbedtls.o
FROMWIREOBJS = $(OBJDIR)/fromwire.o $(VERIFYOBJS) $(OBJDIR)/wireutils.o
IOOBJS       = $(OBJDIR)/ioloop.o $(OBJDIR)/tls-mbedtls.o
CFOBJS       = $(OBJDIR)/config-parse.o

$(BUILDDIR)/dnssd-relay:  $(OBJDIR)/dnssd-relay.o $(DSOOBJS) $(IOOBJS) $(CFOBJS)
	$(CC) -o $@ $+ $(SRPLDOPTS)

$(BUILDDIR)/dnssd-proxy:  $(OBJDIR)/dnssd-proxy.o $(SIMPLEOBJS) $(DSOOBJS) $(MDNSOBJS) $(FROMWIREOBJS) $(IOOBJS) $(CFOBJS)
	$(CC) -o $@ $+ $(SRPLDOPTS)

$(BUILDDIR)/srp-simple:	$(OBJDIR)/srp-simple.o $(SIMPLEOBJS)
	$(CC) -o $@ $+ $(SRPLDOPTS)

$(BUILDDIR)/srp-gw:	$(OBJDIR)/srp-gw.o $(SIMPLEOBJS) $(FROMWIREOBJS) $(IOOBJS) $(HMACOBJS) $(CFOBJS)
	$(CC) -o $@ $+ $(SRPLDOPTS)

$(BUILDDIR)/keydump:	$(OBJDIR)/keydump.o $(SIMPLEOBJS) $(FROMWIREOBJS)
	$(CC) -o $@ $+ $(SRPLDOPTS)

$(OBJDIR)/dso.o:	../DSO/dso.c
	$(CC) -o $@ $(SRPCFLAGS) $(CFLAGS) -c -I. -I../mDNSShared $<

$(OBJDIR)/dnssd_clientstub.o:  ../mDNSShared/dnssd_clientstub.c
	$(CC) -o $@ $(SRPCFLAGS) $(CFLAGS) -c -I. -I../mDNSShared $<

$(OBJDIR)/dnssd_ipc.o:  ../mDNSShared/dnssd_ipc.c
	$(CC) -o $@ $(SRPCFLAGS) $(CFLAGS) -c -I. -I../mDNSShared $<

$(OBJDIR)/%.o:	%.c
	$(CC) -o $@ $(SRPCFLAGS) $(CFLAGS) -c  $<

-include .depfile-config-parse.c
-include .depfile-dnssd-proxy.c
-include .depfile-dnssd_clientstub.c
-include .depfile-dnssd_ipc.c
-include .depfile-dso.c
-include .depfile-fromwire.c
-include .depfile-hash-mbedtls.c
-include .depfile-ioloop.c
-include .depfile-keydump.c
-include .depfile-sign-mbedtls.c
-include .depfile-srp-gw.c
-include .depfile-srp-simple.c
-include .depfile-tls-mbedtls.c
-include .depfile-towire.c
-include .depfile-verify-mbedtls.c
-include .depfile-wireutils.c
