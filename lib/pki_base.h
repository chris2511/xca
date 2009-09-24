/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef PKI_BASE_H
#define PKI_BASE_H

#include <openssl/err.h>
#include <qstring.h>
#include <qlistview.h>
#include "db.h"
#include "base.h"

class pki_base : public QObject
{
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

		void my_error(const QString myerr) const;
		void check_oom(const void *ptr) const;
		void fopen_error(const QString fname);

	public:
		static bool ign_openssl_error();
		QList<pki_base*> childItems;
		pki_base(const QString d = "", pki_base *p = NULL);
		virtual void fload(const QString) {};
		virtual void writeDefault(const QString){};
		static int get_pki_counter(void);
		virtual void fromData(const unsigned char *, db_header_t *){};
		virtual void oldFromData(unsigned char *p, int size);
		virtual unsigned char *toData(int *) { return NULL; }
		virtual bool compare(pki_base *) { return false; };
		virtual ~pki_base();
		QString getIntName() const;
		QString getUnderlinedName() const;
		void setIntName(const QString &d);
		QString getClassName();
		static QString rmslashdot(const QString &fname);

		void openssl_error(const QString myerr = "") const;
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
		virtual void fromPEM_BIO(BIO *, QString) {};
};

#endif
