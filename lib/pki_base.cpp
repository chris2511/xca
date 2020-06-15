/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "func.h"
#include "xfile.h"
#include "pki_base.h"
#include "exception.h"
#include "widgets/XcaWarning.h"
#include <QString>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <typeinfo>

pki_lookup Store;

QRegExp pki_base::limitPattern;
bool pki_base::pem_comment;
QList<pki_base*> pki_base::allitems;

pki_base::pki_base(const QString &name, pki_base *p)
{
	desc = name;
	parent = p;
	childItems.clear();
	pkiType=none;
	pkiSource=unknown;
	allitems << this;
	qDebug() << "NEW pki_base::count" << allitems.count();
}

pki_base::pki_base(const pki_base *p)
{
	desc = p->desc;
	parent = p->parent;
	childItems.clear();
	pkiType = p->pkiType;
	pkiSource = p->pkiSource;
	allitems << this;
	qDebug() << "COPY pki_base::count" << allitems.count();
	p->inheritFilename(this);
}

pki_base::~pki_base(void)
{
	if (!allitems.removeOne(this))
		qDebug() << "DEL" << getIntName() << "NOT FOUND";
	qDebug() << "DEL pki_base::count" << allitems.count();
}

QString pki_base::comboText() const
{
	return desc;
}

void pki_base::autoIntName(const QString &file)
{
	setIntName(rmslashdot(file));
}

void pki_base::deleteFromToken() { }
void pki_base::deleteFromToken(const slotid &) { }
void pki_base::writeDefault(const QString&) const { }
void pki_base::fromPEM_BIO(BIO *, const QString &) { }
void pki_base::fload(const QString &) { }
int pki_base::renameOnToken(const slotid &, const QString &)
{
	return 0;
}

QString pki_base::getUnderlinedName() const
{
	QString name = getIntName();
	QRegExp rx("^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$");

	if (rx.indexIn(name) != -1)
		name += "_";
	return name.replace(QRegExp("[ $&;`/\\\\<>:\"/\\|?*]+"), "_");
}

bool pki_base::visible() const
{
	if (limitPattern.isEmpty())
		return true;
	return getIntName().contains(limitPattern) ||
		comment.contains(limitPattern);
}

void pki_base::PEM_file_comment(XFile &file) const
{
	if (!pem_comment)
		return;
	file.write(QString("XCA internal name: %1\n%2\n")
			.arg(getIntName()).arg(getComment())
				.toUtf8());
}

void pki_base::clear()
{
	childItems.clear();
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

bool pki_base::pem(BioByteArray &, int)
{
	return false;
}

const char *pki_base::getClassName() const
{
	return typeid(*this).name();
}

void pki_base::my_error(const QString &error) const
{
	if (!error.isEmpty()) {
		qCritical() << "Error:" << error;
		throw errorEx(error, getClassName());
	}
}


void pki_base::fromPEMbyteArray(const QByteArray &ba, const QString &name)
{
	fromPEM_BIO(BioByteArray(ba).ro(), name);
	autoIntName(name);
	setFilename(name);
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
	SQL_PREPARE(q, "UPDATE items SET del=1 WHERE id=?");
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

pki_base *pki_base::getParent() const
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

void pki_base::insert(pki_base *item)
{
	if (!childItems.contains(item))
		childItems.prepend(item);
}

int pki_base::childCount() const
{
	return childItems.size();
}

int pki_base::indexOf(const pki_base *child) const
{
	int ret = childItems.indexOf(const_cast<pki_base *>(child));
	return ret >= 0 ? ret : 0;
}

void pki_base::takeChild(pki_base *pki)
{
	childItems.removeOne(pki);
}

QList<pki_base*> pki_base::getChildItems() const
{
	//#warning need to collect all children below folders (later)
	return childItems;
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
		case renewed: return tr("Renewed");
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
unsigned pki_base::hash(const QByteArray &ba)
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

QString pki_base::get_dump_filename(const QString &dir,
				    const QString &ext) const
{
	QString ctr = "", fn;
	int count = 0;
	while (count++ < 1000) {
		fn = dir + "/" + getUnderlinedName() + ctr + ext;
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

void pki_base::collect_properties(QMap<QString, QString> &prp) const
{
	QString t;
	prp["Descriptor"] = getIntName();
	if (getComment().size() > 0)
		prp["Comment"] = "\n" + getComment().replace('\n', "\n    ");
	switch (pkiType) {
	case asym_key:   t = "Asymetric Key"; break;
	case x509_req:   t = "PKCS#10 Certificate request"; break;
	case x509:       t = "x.509 Certificate"; break;
	case revocation: t = "Certificate revocation list"; break;
	case tmpl:       t = "XCA Template"; break;
	default:         t = "Unknown"; break;
	}
	prp["Type"] = t;
}

void pki_base::print(BioByteArray &bba, enum print_opt opt) const
{
	static const QStringList order = {
		"Type", "Descriptor", "Subject", "Issuer", "Serial",
		"Not Before", "Not After", "Verify Ok",
		"Unstructured Name", "Challange Password",
		"Last Update", "Next Update", "CA", "Self signed",
		"Key", "Signature", "Extensions", "Comment",
	};
	if (opt == print_coloured) {
		QMap<QString, QString> prp;
		QStringList keys;
		int w = 0;

		collect_properties(prp);
		keys = prp.keys();

		foreach (const QString &key, keys) {
			if (key.size() > w)
				w = key.size();
			if (!order.contains(key))
				XCA_WARN(tr("Property '%1' not listed in 'pki_base::print'").arg(key));
		}
		w = (w + 1) * -1;
		foreach (const QString &key, order) {
			if (!prp.contains(key))
				continue;

			bba += QString(COL_YELL "%1" COL_RESET " %2\n")
				.arg(key + ":", w).arg(prp[key]).toUtf8();
		}
	}
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
	QString uniqueid = formatHash(Digest(i2d(), EVP_sha1()), "");
	QString desc = icsValue(description + "\n----------\n" + comment);
	QString alarm = Settings["ical_expiry"];
	return QStringList() <<

	"BEGIN:VEVENT" <<
	QString("DTSTAMP:%1").arg(a1time().toString("yyyyMMdd'T'HHmmss'Z'")) <<
	QString("UID:EXP-%1@xca.ovh").arg(uniqueid) <<
	"STATUS:CONFIRMED" <<
	QString("DTSTART:%1").arg(expires.toString("yyyyMMdd")) <<
	"DURATION:P1D" <<
	QString("SUMMARY:%1").arg(icsValue(summary)) <<
	QString("DESCRIPTION:%1").arg(desc) <<
	"BEGIN:VALARM" <<
	"ACTION:DISPLAY" <<
	QString("SUMMARY:%1").arg(icsValue(summary)) <<
	QString("DESCRIPTION:%1").arg(desc) <<
	QString("TRIGGER:-P%1").arg(alarm) <<
	"END:VALARM" <<
	"END:VEVENT";
}
