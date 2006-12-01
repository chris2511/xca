/*
 * Copyright (C) 2001 Christian Hohnstaedt.
 *
 *  All rights reserved.
 *
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *  - Neither the name of the author nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * This program links to software with different licenses from:
 *
 *	http://www.openssl.org which includes cryptographic software
 *	written by Eric Young (eay@cryptsoft.com)"
 *
 *	http://www.trolltech.com
 *
 *
 *
 * http://www.hohnstaedt.de/xca
 * email: christian@hohnstaedt.de
 *
 * $Id$
 *
 */

#ifndef PKI_BASE_H
#define PKI_BASE_H

#include <openssl/err.h>
#include <Qt/qstring.h>
#include <Qt/qlistview.h>
#include "db.h"
#include "base.h"

class pki_base : public QObject
{
	Q_OBJECT

    private:
	static int pki_counter;
    protected:
	int cols;
	const char *class_name;
	QString desc;
	int dataVersion;
	enum pki_type pkiType;
	/* model data */
	pki_base *parent;

	void openssl_error(const QString myerr = "") const;
	void fopen_error(const QString fname);
	bool ign_openssl_error() const;

    public:
	QList<pki_base*> childItems;
	pki_base(const QString d = "", pki_base *p = NULL);
	virtual void fload(const QString name){};
	virtual void writeDefault(const QString fname){};
	static int get_pki_counter(void);
	virtual void fromData(const unsigned char *p, db_header_t *head){};
	virtual void oldFromData(unsigned char *p, int size);
	virtual unsigned char *toData(int *size){return NULL;}
	virtual bool compare(pki_base *ref){return false;}
	virtual ~pki_base();
        QString getIntName() const;
	QString getUnderlinedName() const;
        void setIntName(const QString &d);
	QString getClassName();
	static QString rmslashdot(const QString &fname);
	//virtual void updateView();

	int getVersion();
	enum pki_type getType();
	void setParent(pki_base *p);
	virtual pki_base *getParent();
	pki_base *child(int row);
	void append(pki_base *item);
	void insert(int row, pki_base *item);
	int childCount();
	int row() const;
	pki_base *iterate(pki_base *pki = NULL);
	void takeChild(pki_base *pki);
	pki_base *takeFirst();
	int columns();
	virtual QVariant column_data(int col);
	virtual QVariant getIcon();
	const char *className() { return class_name; };
	uint32_t intFromData(const unsigned char **p);
};

#endif
