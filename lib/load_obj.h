/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#ifndef __LOAD_OBJ_H
#define __LOAD_OBJ_H

#include <QStringList>

class pki_base;

class load_base
{
	public:
		QString filter;
		QString caption;
		load_base();
		virtual ~load_base();
		virtual pki_base *loadItem(QString s);
		virtual pki_base *newItem();
};

class load_key: public load_base
{
	public:
		load_key();
		pki_base *newItem();
};

class load_req: public load_base
{
	public:
		load_req();
		pki_base *newItem();
};

class load_cert: public load_base
{
	public:
		load_cert();
		pki_base *newItem();
};

class load_pkcs7: public load_base
{
	public:
		load_pkcs7();
		pki_base *newItem();
};

class load_pkcs12: public load_base
{
	public:
		load_pkcs12();
		pki_base *loadItem(QString s);
};

class load_temp: public load_base
{
	public:
		load_temp();
		pki_base *newItem();
};

class load_crl: public load_base
{
	public:
		load_crl();
		pki_base *newItem();
};

class load_db: public load_base
{
	public:
		load_db();
};

class load_pkcs11: public load_base
{
	public:
		load_pkcs11();
};

class load_pem: public load_base
{
	public:
		load_pem();
		pki_base *newItem();
};

#endif
