/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2013 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "func.h"
#include "pki_base.h"
#include "exception.h"
#include <QString>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <typeinfo>

QRegExp pki_base::limitPattern;

pki_base::pki_base(const QString name, pki_base *p)
{
	desc = name;
	parent = p;
	childItems.clear();
	pkiType=none;
	pkiSource=unknown;
}

pki_base::~pki_base(void)
{
	while (childItems.size() > 0)
		delete takeFirst();
}

QString pki_base::comboText() const
{
	return desc;
}

void pki_base::autoIntName()
{
	setIntName("");
}

void pki_base::deleteFromToken() { };
void pki_base::deleteFromToken(slotid) { };
void pki_base::writeDefault(const QString) { }
void pki_base::fromPEM_BIO(BIO *, QString) { }
void pki_base::fload(const QString) { }
int pki_base::renameOnToken(slotid, QString)
{
	return 0;
}

bool pki_base::visible() const
{
	if (limitPattern.isEmpty())
		return true;
	return getIntName().contains(limitPattern) ||
		comment.contains(limitPattern);
}

bool pki_base::childVisible() const
{
	foreach(pki_base *child, childItems)
		if (child->isVisible())
			return true;
	return false;
}

int pki_base::isVisible()
{
	if (limitPattern.isEmpty())
		return 1;
	return visible() ? 1 : childVisible() ? 2 : 0;
}

QString pki_base::getMsg(msg_type msg) const
{
	return tr("Internal error: Unexpected message: %1 %2")
		.arg(getClassName()).arg(msg);
}

QByteArray pki_base::i2d() const
{
	return QByteArray();
}

BIO *pki_base::pem(BIO *, int format)
{
	(void)format;
	return NULL;
}

const char *pki_base::getClassName() const
{
	return typeid(*this).name();
}

void pki_base::fopen_error(const QString fname)
{
	my_error(tr("Error opening file: '%1': %2").
			arg(fname).
			arg(strerror(errno)));
}

void pki_base::fwrite_ba(FILE *fp, QByteArray ba, QString fname)
{
	if (fwrite(ba.constData(), 1, ba.size(), fp) != (size_t)ba.size()) {
		my_error(tr("Error writing to file: '%1': %2").
			arg(fname).
			arg(strerror(errno)));
        }
}

void pki_base::my_error(const QString error) const
{
	if (!error.isEmpty()) {
		qCritical() << "Error:" << error;
		throw errorEx(error, getClassName());
	}
}


void pki_base::fromPEMbyteArray(QByteArray &ba, QString name)
{
	BIO *bio = BIO_new_mem_buf(ba.data(), ba.length());
	fromPEM_BIO(bio, name);
	BIO_free(bio);
	autoIntName();
	if (getIntName().isEmpty())
		setIntName(rmslashdot(name));
}

QString pki_base::rmslashdot(const QString &s)
{
	QByteArray a = s.toLatin1().replace("\\", "/");
	int r = a.lastIndexOf('.');
	int l = a.lastIndexOf('/');
	return s.mid(l+1,r-l-1);
}

QSqlError pki_base::insertSql()
{
	XSqlQuery q;
	QString insert;
	QSqlError e;
	insertion_date.now();

	SQL_PREPARE(q, "SELECT MAX(id) +1 from items");
	q.exec();
	if (q.first())
		sqlItemId = q.value(0);

	if (sqlItemId.toULongLong() == 0)
		sqlItemId = 1;

	SQL_PREPARE(q, "INSERT INTO items "
		  "(id, name, type, date, source, comment) "
		  "VALUES (?, ?, ?, ?, ?, ?)");
	q.bindValue(0, sqlItemId);
	q.bindValue(1, getIntName());
	q.bindValue(2, getType());
	q.bindValue(3, insertion_date.toPlain());
	q.bindValue(4, pkiSource);
	q.bindValue(5, getComment());
	q.exec();
	e = q.lastError();
	if (!e.isValid()) {
		e = insertSqlData();
	}
	return e;
}

void pki_base::restoreSql(const QSqlRecord &rec)
{
	sqlItemId = rec.value(VIEW_item_id);
	desc = rec.value(VIEW_item_name).toString();
	insertion_date.fromPlain(rec.value(VIEW_item_date).toString());
	comment = rec.value(VIEW_item_comment).toString();
	pkiSource = (enum pki_source)rec.value(VIEW_item_source).toInt();
}

QSqlError pki_base::deleteSql()
{
	XSqlQuery q;
	QString insert;
	QSqlError e;

	if (!sqlItemId.isValid()) {
		qDebug("INVALID sqlItemId (DELETE %s)", CCHAR(getIntName()));
		return sqlItemNotFound(QVariant());
	}
	e = deleteSqlData();
	if (e.isValid())
		return e;
	SQL_PREPARE(q, "DELETE FROM items WHERE id=?");
	q.bindValue(0, sqlItemId);
	q.exec();
	return q.lastError();
}

QSqlError pki_base::sqlItemNotFound(QVariant sqlId) const
{
	return QSqlError(QString("XCA SQL database inconsistent"),
			QString("Item %2 not found %1")
				.arg(getClassName())
				.arg(sqlId.toString()),
			QSqlError::UnknownError);
}

pki_base *pki_base::getParent()
{
	return parent;
}

void pki_base::setParent(pki_base *p)
{
	parent = p;
}

pki_base *pki_base::child(int row)
{
	return childItems.value(row);
}

void pki_base::append(pki_base *item)
{
	childItems.append(item);
	item->setParent(this);
}

void pki_base::insert(int row, pki_base *item)
{
	childItems.insert(row, item);
	item->setParent(this);
}

int pki_base::childCount() const
{
	return childItems.size();
}

int pki_base::row(void) const
{
	if (parent)
		return parent->childItems.indexOf(const_cast<pki_base*>(this));
	return 0;
}

pki_base *pki_base::iterate(pki_base *pki)
{
	if (pki == NULL)
		pki = (childItems.isEmpty()) ? NULL : childItems.first();
	else
		pki = childItems.value(pki->row()+1);

	if (pki) {
		return pki;
	}
	if (!parent) {
		return NULL;
	}
	return parent->iterate(this);
}

void pki_base::takeChild(pki_base *pki)
{
	childItems.takeAt(pki->row());
}

pki_base *pki_base::takeFirst()
{
	return childItems.takeFirst();
}

QString pki_base::pki_source_name() const
{
	switch (pkiSource) {
		default:
		case unknown: return tr("Unknown");
		case imported: return tr("Imported");
		case generated: return tr("Generated");
		case transformed: return tr("Transformed");
		case token: return tr("Token");
		case legacy_db: return tr("Legacy Database");
	}
	return QString("???");
}

QVariant pki_base::column_data(const dbheader *hd) const
{
	switch (hd->id) {
	case HD_internal_name:
		return QVariant(getIntName());
	case HD_comment:
		return QVariant(comment.section('\n', 0, 0));
	case HD_source:
		return QVariant(pki_source_name());
	case HD_primary_key:
		return sqlItemId;
	}
	if (hd->type == dbheader::hd_asn1time) {
		a1time t = column_a1time(hd);
		if (!t.isUndefined())
			return QVariant(t.toFancy());
	}
	return QVariant();
}

a1time pki_base::column_a1time(const dbheader *hd) const
{
	switch (hd->id) {
	case HD_creation:
		return insertion_date;
	}
	return a1time().setUndefined();
}

QVariant pki_base::getIcon(const dbheader *hd) const
{
	(void)hd;
	return QVariant();
}

QVariant pki_base::column_tooltip(const dbheader *hd) const
{
	switch (hd->id) {
	case HD_comment:
		return QVariant(comment);
	}
	if (hd->type == dbheader::hd_asn1time) {
		a1time t = column_a1time(hd);
		if (!t.isUndefined())
			return QVariant(t.toPretty());
	}
	return QVariant();
}

bool pki_base::compare(const pki_base *ref) const
{
	bool ret;
	ret = (i2d() == ref->i2d());
	pki_openssl_error();
	return ret;
}

/* Unsigned 32 bit integer */
unsigned pki_base::hash(QByteArray ba)
{
	unsigned char md[EVP_MAX_MD_SIZE];

	SHA1((const unsigned char *)ba.constData(), ba.length(), md);

	return (((unsigned)md[0]     ) | ((unsigned)md[1]<<8L) |
		((unsigned)md[2]<<16L) | ((unsigned)md[3]<<24L)
		) & 0x7fffffffL;
}
unsigned pki_base::hash() const
{
	return hash(i2d());
}

QString pki_base::get_dump_filename(const QString &dir, QString ext)
{
	QString ctr = "", fn;
	int count = 0;
	while (count++ < 1000) {
		fn = dir +QDir::separator() +getUnderlinedName() +ctr +ext;
		if (!QFile::exists(fn))
			return fn;
		ctr = QString("_%1").arg(count);
	}
	return fn;
}

void pki_base::selfComment(QString msg)
{
	setComment(appendXcaComment(getComment(), msg));
}

static QString icsValue(QString s)
{
	int n = 60;
	QStringList lines;

	QString t = s.replace(QRegExp("([,;\\\\])"), "\\\\1")
			.replace("\n", "\\n")
			.replace("\r", "\\r");
	qDebug() << "S:" << s;
	for (int j = n; !s.isEmpty(); j--) {
		QString sub = s.left(j);
		if (sub.endsWith("\\") || sub.toUtf8().length() > n)
			continue;
		s.remove(0, j);
		lines << sub;
		j = n = 74;
	}
	return lines.join("\r\n ");
}

QStringList pki_base::icsVEVENT(const a1time &expires,
	const QString &summary, const QString &description) const
{
	QByteArray ba = i2d();
	unsigned char md[MD5_DIGEST_LENGTH];
	MD5((const unsigned char *)ba.constData(), ba.length(), md);
	QString uniqueid = formatHash(md, MD5_DIGEST_LENGTH, false);
	QString desc = icsValue(description + "\n----------\n" + comment);
	QString alarm = Settings["ical_expiry"];
	return QStringList() <<

	"BEGIN:VEVENT" <<
	QString("DTSTAMP:%1").arg(a1time().toString("yyyyMMdd'T'HHmmss'Z'")) <<
	QString("UID:EXP-%1@xca.ovh").arg(uniqueid) <<
	"STATUS:NEEDS-ACTION" <<
	QString("DTSTART:%1").arg(expires.toString("yyyyMMdd")) <<
	"DURATION:P1D" <<
	QString("SUMMARY:%1").arg(icsValue(summary)) <<
	QString("DESCRIPTION:%1").arg(desc) <<
	"BEGIN:VALARM" <<
	"ACTION:EMAIL" <<
	QString("SUMMARY:%1").arg(icsValue(summary)) <<
	QString("DESCRIPTION:%1").arg(desc) <<
	QString("TRIGGER:-P%1").arg(alarm) <<
	"END:VALARM" <<
	"END:VEVENT";
}
