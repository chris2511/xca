/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __X509V3EXT_H
#define __X509V3EXT_H

#include <QList>
#include <QStringList>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

class QString;

class x509v3ext
{
   private:
	X509_EXTENSION *ext;
	const ASN1_OBJECT *object() const;
   public:
	x509v3ext();
	x509v3ext(const X509_EXTENSION *n);
	x509v3ext(const x509v3ext &n);
	~x509v3ext();
	x509v3ext &set(const X509_EXTENSION *n);
	x509v3ext &create(int nid, const QString &et, X509V3_CTX *ctx = NULL);
	x509v3ext &create_ia5(int nid, const QString &et,
				X509V3_CTX *ctx = NULL);
	x509v3ext &operator = (const x509v3ext &x);
	// bool operator == (const x509v3ext &x) const;
	QString getObject() const;
	int getCritical() const;
	QString getValue(bool html=false) const;
	QString getHtml() const;
	X509_EXTENSION *get() const;
	bool isValid() const;
	int nid() const;
	void *d2i() const;
	bool genConf(QString *single, QString *adv) const;
	bool parse_generic(QString *single, QString *adv) const;
    protected:
	QString parse_critical() const;
	bool parse_certpol(QString *single, QString *adv) const;
	bool parse_ainfo(QString *single, QString *adv) const;
	bool parse_Crldp(QString *single, QString *adv) const;
	bool parse_eku(QString *single, QString *adv) const;
	bool parse_generalName(QString *single, QString *adv) const;
	bool parse_ia5(QString *single, QString *adv) const;
	bool parse_bc(QString *single, QString *adv) const;
	bool parse_bitstring(QString *single, QString *adv) const;
	bool parse_sKeyId(QString *single, QString *adv) const;
	bool parse_aKeyId(QString *single, QString *adv) const;
	bool parse_inhibitAnyPolicy(QString *, QString *adv) const;
	bool parse_policyConstraints(QString *, QString *adv) const;
	bool parse_policyMappings(QString *, QString *adv) const;
	bool parse_nameConstraints(QString *, QString *adv) const;
};

class extList : public QList<x509v3ext>
{
    public:
	void setStack(STACK_OF(X509_EXTENSION) *st, int start=0);
	STACK_OF(X509_EXTENSION) *getStack();
	QString getHtml(const QString &sep);
	bool delByNid(int nid);
	int delInvalid();
	int idxByNid(int nid);
	bool genConf(int nid, QString *single, QString *adv = NULL);
	void genGenericConf(QString *adv);
	bool search(const QRegExp &pattern);
};
#endif
