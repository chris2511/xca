CPPFLAGS=-I. -I.. -I/usr/include/qt
CFLAGS=-Wall -O2

LDFLAGS=
LIBS=-lstdc++ -ldb3_cxx -lqt -lcrypto

MOC=moc
UIC=uic

CC=gcc
LD=ld
STRIP=strip

prefix=/usr
destdir=$(CURDIR)/debian/xca
bindir=X11R6/bin
mandir=X11R6/man
