/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __PKI_BASE_H
#define __PKI_BASE_H

#include <openssl/err.h>
#include <qstring.h>
#include <qlistview.h>
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

		void my_error(const QString myerr) const;
		void fopen_error(const QString fname);

	public:
		static void openssl_error(const QString myerr = "");
		QList<pki_base*> childItems;
		pki_base(const QString d = "", pki_base *p = NULL);
		virtual void fload(const QString) {};
		virtual void writeDefault(const QString) {};
		static int get_pki_counter(void);
		virtual void fromData(const unsigned char *, db_header_t *) {};
		virtual void oldFromData(unsigned char *p, int size);
		virtual QByteArray toData()
		{
			return QByteArray();
		}
		virtual bool compare(pki_base *)
		{
			return false;
		};
		virtual ~pki_base();
		QString getIntName() const;
		QString getUnderlinedName() const;
		void setIntName(const QString &d);
		QString getClassName();
		static QString rmslashdot(const QString &fname);
		virtual QString getFriendlyClassName()
		{
			return QString("---");
		};
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
		virtual QVariant getIcon(int column);
		const char *className()
		{
			return class_name;
		};
		uint32_t intFromData(QByteArray &ba);
		virtual void fromPEM_BIO(BIO *, QString) {};
		virtual void deleteFromToken() { };
		virtual void deleteFromToken(unsigned long slot) { };
		virtual int renameOnToken(unsigned long slot, QString name)
		{
			return 0;
		};
};

#endif
