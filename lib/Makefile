VERSION=0.1.5
TARGET=xca-$(VERSION)
GCC=c++
INC=-I$(QTDIR)/include
LPATH=-L$(QTDIR)/lib
LIBS=-lqt -lcrypto -ldb_cxx

PKIOBJS=pki_base.o pki_key.o pki_x509req.o
DBOBJS=db_base.o
     

all: libpki.a libxcadb.a

libpki.a: $(PKIOBJS)
	ar rcs libpki.a $(PKIOBJS)

libxcadb.a: $(DBOBJS)
	ar rcs libxcadb.a $(DBOBJS)
	
%.o: %.cpp %.h
	$(GCC) -c $(INC) $<

clean:
	rm -rf *~ *.o *.a

