BUILDDIR = build
OBJDIR = objects

SYSTEM := $(shell uname -s)
ifeq ($(SYSTEM), Darwin)
  os=x
else ifeq ($(SYSTEM), Linux)
  os=linux
endif

ifeq ($(os),x)
SRPCFLAGS = -O0 -g -Wall -Werror -DSTANDALONE -I../mDNSCore -I/usr/local/include -I. -I../mDNSShared -I../DSO -MMD -MF .depfile-${notdir $<} -DUSE_SELECT
LINKOPTS = -lmbedcrypto -lmbedtls -lmbedx509
else ifeq ($(os), linux)
SRPCFLAGS = -O0 -g -Wall -Werror -DSTANDALONE -I../mDNSCore -I/usr/local/include -I. -I../mDNSShared -I../DSO -MMD -MF .depfile-${notdir $<} -DNOT_HAVE_SA_LEN -DUSE_SELECT
LINKOPTS = -lmbedcrypto -lmbedtls -lmbedx509
endif

all:	setup $(BUILDDIR)/srp-simple $(BUILDDIR)/srp-gw $(BUILDDIR)/keydump $(BUILDDIR)/dnssd-proxy

# 'setup' sets up the build directory structure the way we want
setup:
	@if test ! -d $(OBJDIR)   ; then mkdir -p $(OBJDIR)   ; fi
	@if test ! -d $(BUILDDIR) ; then mkdir -p $(BUILDDIR) ; fi

# clean removes targets and objects
clean:
	@if test -d $(OBJDIR)   ; then rm -r $(OBJDIR)   ; fi
	@if test -d $(BUILDDIR) ; then rm -r $(BUILDDIR) ; fi

SIGNOBJS     = $(OBJDIR)/sign-mbedtls.o 
SIMPLEOBJS   = $(OBJDIR)/towire.o $(SIGNOBJS)
DSOOBJS      = $(OBJDIR)/dso.o
MDNSOBJS     = $(OBJDIR)/dnssd_clientstub.o $(OBJDIR)/dnssd_ipc.o
VERIFYOBJS   = $(OBJDIR)/verify-mbedtls.o
FROMWIREOBJS = $(OBJDIR)/fromwire.o $(VERIFYOBJS) $(OBJDIR)/wireutils.o
IOOBJS       = $(OBJDIR)/ioloop.o $(OBJDIR)/tls-mbedtls.o
CFOBJS       = $(OBJDIR)/config-parse.o

$(BUILDDIR)/dnssd-proxy:  $(OBJDIR)/dnssd-proxy.o $(SIMPLEOBJS) $(DSOOBJS) $(MDNSOBJS) $(FROMWIREOBJS) $(IOOBJS) $(CFOBJS)
	$(CC) -o $@ $+ $(LINKOPTS)

$(BUILDDIR)/srp-simple:	$(OBJDIR)/srp-simple.o $(SIMPLEOBJS)
	$(CC) -o $@ $+ $(LINKOPTS)

$(BUILDDIR)/srp-gw:	$(OBJDIR)/srp-gw.o $(SIMPLEOBJS) $(FROMWIREOBJS) $(IOOBJS)
	$(CC) -o $@ $+ $(LINKOPTS)

$(BUILDDIR)/keydump:	$(OBJDIR)/keydump.o $(SIMPLEOBJS) $(FROMWIREOBJS)
	$(CC) -o $@ $+ $(LINKOPTS)

$(OBJDIR)/dso.o:	../DSO/dso.c
	$(CC) -o $@ $(SRPCFLAGS) -c -I. -I../mDNSShared $<

$(OBJDIR)/dnssd_clientstub.o:  ../mDNSShared/dnssd_clientstub.c
	$(CC) -o $@ $(SRPCFLAGS) -c -I. -I../mDNSShared $<

$(OBJDIR)/dnssd_ipc.o:  ../mDNSShared/dnssd_ipc.c
	$(CC) -o $@ $(SRPCFLAGS) -c -I. -I../mDNSShared $<

$(OBJDIR)/%.o:	%.c
	$(CC) -o $@ $(SRPCFLAGS) -c  $<

-include .depfile-dnssd-proxy.c
-include .depfile-fromwire.c
-include .depfile-wireutils.c
-include .depfile-ioloop.c
-include .depfile-keydump.c
-include .depfile-sign-mbedtls.c
-include .depfile-srp-gw.c
-include .depfile-srp-simple.c
-include .depfile-towire.c
-include .depfile-verify-mbedtls.c
-include .depfile-tls-mbedtls.c
-include .depfile-dso.c
-include .depfile-DNSCommon.c
