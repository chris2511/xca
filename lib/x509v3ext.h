/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2009 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef X509V3EXT_H
#define X509V3EXT_H

#include <qlist.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

class QString;

class x509v3ext
{
   private:
	X509_EXTENSION *ext;
   public:
	x509v3ext();
	x509v3ext(const X509_EXTENSION *n);
	x509v3ext(const x509v3ext &n);
	~x509v3ext();
	x509v3ext &set(const X509_EXTENSION *n);
	x509v3ext &create(int nid, const QString &et, X509V3_CTX *ctx = NULL);
	x509v3ext &operator = (const x509v3ext &x);
	// bool operator == (const x509v3ext &x) const;
	QString getObject() const;
	int getCritical() const;
	QString getValue() const;
	QString getHtml() const;
	X509_EXTENSION *get() const;
	bool isValid() const;
	int nid() const;
	void *d2i();
};

class extList : public QList<x509v3ext>
{
    public:
	void setStack(STACK_OF(X509_EXTENSION) *st, int start=0);
	STACK_OF(X509_EXTENSION) *getStack();
	QString getHtml(const QString &sep);
	int delByNid(int nid);
	int delInvalid();
	int idxByNid(int nid);
};
#endif
