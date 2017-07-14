/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2012 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __PKI_BASE_H
#define __PKI_BASE_H

#include <openssl/err.h>
#include <QString>
#include <QListView>
#include <QtSql>
#include "asn1time.h"
#include "pkcs11_lib.h"
#include "db.h"
#include "base.h"
#include "headerlist.h"

#define __ME QString("(%1:%2)").arg(getClassName()).arg(getIntName())
#define pki_openssl_error() _openssl_error(__ME, C_FILE, __LINE__)
#define pki_ign_openssl_error() _ign_openssl_error(__ME, C_FILE, __LINE__)

#define SQL_PREPARE(q,cmd) do { \
	(q).prepare(cmd); \
	(q).location(__FILE__,__LINE__); \
} while (0)

enum pki_source {
	unknown,
	imported,
	generated,
	transformed
};

#define VIEW_item_id 0
#define VIEW_item_name 1
#define VIEW_item_type 2
#define VIEW_item_date 3
#define VIEW_item_source 4
#define VIEW_item_comment 5

class XSqlQuery: public QSqlQuery
{
		QString lastq;
		const char *file;
		int line;
	public:
		QString query_details()
		{
			QString lq = lastq;
			QList<QVariant> list = boundValues().values();
			QStringList sl;
			for (int i = 0; i < list.size(); ++i)
				sl << list.at(i).toString();
			if (sl.size())
				lq += QString("[%1]").arg(sl.join(", "));
			return QString("%1:%2 (%3)")
				.arg(file).arg(line).arg(lq);
		}
		QSqlError lastError()
		{
			QSqlError e = QSqlQuery::lastError();
			if (!e.isValid())
				return e;
			QString dt = e.driverText();
			e.setDriverText(QString("%1 - %2")
				.arg(dt).arg(query_details()));
			return e;
		}
		XSqlQuery() : QSqlQuery() { }
		XSqlQuery(QString q) : QSqlQuery(q)
		{
			file = ""; line = 0;
			lastq = q;
		}
		bool exec(QString q)
		{
			lastq = q;
			file = ""; line = 0;
			return QSqlQuery::exec(q);
		}
		bool exec()
		{
			QString res;
			setForwardOnly(true);
			bool r = QSqlQuery::exec();
			if (isSelect())
				res = QString("Rows selected: %1").arg(size());
			else
				res = QString("Rows affected: %1")
					.arg(numRowsAffected());
			qDebug() << QString("QUERY: %1 - %2")
					.arg(query_details()).arg(res);
			return r;
		}
		bool prepare(QString q)
		{
			lastq = q;
			setForwardOnly(true);
			return QSqlQuery::prepare(q);
		}
		void location(const char *f, int l)
		{
			file = f; line = l;
		}
};

class pki_base : public QObject
{
		Q_OBJECT

	public: /* static */
		static int suppress_messages;
		static QRegExp limitPattern;
		static QString rmslashdot(const QString &fname);
		static unsigned hash(QByteArray ba);

	protected:
		QVariant sqlItemId;
		QString desc, comment;
		a1time insertion_date;
		enum pki_type pkiType;
		/* model data */
		pki_base *parent;
		void my_error(const QString myerr) const;
		void fopen_error(const QString fname);

	public:
		enum msg_type {
			msg_import,
			msg_delete,
			msg_delete_multi,
			msg_create,
		};
		enum pki_source pkiSource;
		QList<pki_base*> childItems;

		pki_base(const QString d = "", pki_base *p = NULL);
		virtual ~pki_base();

		QString getIntName() const
		{
			return desc;
		}
		virtual QString comboText() const;
		QString getUnderlinedName() const
		{
			return getIntName().replace(
				QRegExp("[ &;`/\\\\]+"), "_");
		}
		void setIntName(const QString &d)
		{
			desc = d;
		}
		QString getComment() const
		{
			return comment;
		}
		void setComment(QString c)
		{
			comment = c;
		}
		QVariant getSqlItemId()
		{
			return sqlItemId;
		}
		enum pki_type getType() const
		{
			return pkiType;
		}
		QString i2d_b64()
		{
			return QString::fromLatin1(i2d().toBase64());
		}
		virtual QByteArray i2d();
		virtual bool compare(pki_base *);
		virtual QString getMsg(msg_type msg);
		virtual const char *getClassName() const;

		/* Tree View management */
		void setParent(pki_base *p);
		virtual pki_base *getParent();
		pki_base *child(int row);
		void append(pki_base *item);
		void insert(int row, pki_base *item);
		int childCount();
		pki_base *iterate(pki_base *pki = NULL);
		void takeChild(pki_base *pki);
		pki_base *takeFirst();

		/* Token handling */
		virtual void deleteFromToken();
		virtual void deleteFromToken(slotid);
		virtual int renameOnToken(slotid, QString);

		/* Import / Export management */
		virtual BIO *pem(BIO *, int format=0);
		virtual void fromPEM_BIO(BIO *, QString);
		virtual void fromPEMbyteArray(QByteArray &, QString);
		void fwrite_ba(FILE *fp, QByteArray ba, QString fname);
		virtual void fload(const QString);
		virtual void writeDefault(const QString);

		/* Old database management methods */
		virtual void fromData(const unsigned char *, db_header_t *) {};
		/* Qt Model-View methods */
		virtual QVariant bg_color(dbheader *hd)
		{
			(void)hd;
			return QVariant();
		}
		int row() const;
		virtual QVariant column_data(dbheader *hd);
		virtual QVariant getIcon(dbheader *hd);
		virtual bool visible();


		/* SQL management methods */
		QSqlError insertSql();
		virtual QSqlError insertSqlData()
		{
			return QSqlError();
		}
		QSqlError deleteSql();
		virtual QSqlError deleteSqlData()
		{
			return QSqlError();
		}
		virtual void restoreSql(QSqlRecord &rec);
		QSqlError sqlItemNotFound(QVariant sqlId) const;
		unsigned hash();
		QString pki_source_name() const;
};

Q_DECLARE_METATYPE(pki_base *);
#endif
