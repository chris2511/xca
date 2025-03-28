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
#include "XcaWarningCore.h"
#include <QString>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/md5.h>

pki_lookup Store;

QRegularExpression pki_base::limitPattern;
bool pki_base::pem_comment;
QBrush pki_base::red, pki_base::cyan, pki_base::yellow;

pki_base::pki_base(const QString &name) : desc(name)
{
}

pki_base::pki_base(const pki_base *p)
{
	desc = p->desc;
	pkiType = p->pkiType;
	pkiSource = p->pkiSource;
	p->inheritFilename(this);
}

pki_base::~pki_base(void)
{
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
	QRegularExpression rx("^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$");

	if (rx.match(name).hasMatch())
		name += "_";
	return name.replace(QRegularExpression("[ $&;`/\\\\<>:\"/\\|?*]+"), "_");
}

bool pki_base::visible() const
{
	return getIntName().contains(limitPattern) ||
		comment.contains(limitPattern);
}

QByteArray pki_base::PEM_comment() const
{
	if (!pem_comment)
		return QByteArray();

	return QString("XCA internal name: %1\n%2\n")
			.arg(getIntName()).arg(getComment()).toUtf8();
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
	qDebug() << limitPattern << lastPattern;
	if (limitPattern.pattern().isEmpty())
		iamvisible = 1;
	else if (limitPattern != lastPattern) {
		lastPattern = limitPattern;
		iamvisible = visible() ? 1 : childVisible() ? 2 : 0;
	}
	return iamvisible;
}

QString pki_base::getMsg(msg_type msg, int) const
{
	return tr("Internal error: Unexpected message: %1 %2")
		.arg(getClassName()).arg(msg);
}

QByteArray pki_base::i2d() const
{
	return QByteArray();
}

bool pki_base::pem(BioByteArray &)
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
	if (!childItems.contains(item)) {
		childItems.prepend(item);
		item->setParent(this);
	}
}

int pki_base::childCount() const
{
	return childItems.size();
}

int pki_base::indexOf(const pki_base *child) const
{
	return childItems.indexOf(const_cast<pki_base *>(child));
}

void pki_base::takeChild(pki_base *pki)
{
	if (childItems.removeOne(pki))
		pki->setParent(nullptr);
}

QList<pki_base*> pki_base::getChildItems() const
{
	//#warning need to collect all children below folders (later)
	return childItems;
}

pki_base *pki_base::takeFirst()
{
	pki_base *pki = childItems.takeFirst();
	if (pki)
		 pki->setParent(nullptr);
	return pki;
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
	if (!hashcache)
		hashcache = hash(i2d());
	return hashcache;
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
	prp["Type"] = getTypeString();
}

QString pki_base::getTypeString() const
{
	QString t;
	switch (pkiType) {
	case asym_key:   t = "Asymmetric Key"; break;
	case x509_req:   t = "PKCS#10 Certificate request"; break;
	case x509:       t = "x.509 Certificate"; break;
	case revocation: t = "Certificate revocation list"; break;
	case tmpl:       t = "XCA Template"; break;
	case smartCard:  t = "Token Key"; break;
	default:         t = "Unknown"; break;
	}
	return t;
}

void pki_base::print(BioByteArray &bba, enum print_opt opt) const
{
	static const QStringList order = {
		"Type", "Descriptor", "Subject", "Issuer", "Serial",
		"Not Before", "Not After", "Verify Ok",
		"Unstructured Name", "Challenge Password",
		"Last Update", "Next Update", "CA", "Self signed",
		"Key", "Signature", "Extensions", "Comment", "Algorithm",
		"Friendly Name"
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

	QString t = s.replace(QRegularExpression("([,;\\\\])"), "\\\\1")
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

void pki_base::setupColors(const QPalette &pal)
{
	int factor = 50;
	if (pal.window().color().value() > pal.windowText().color().value())
		factor = 125;

	qDebug() << "WindowColor" << pal.window().color().value()
			 << "TextColor" << pal.windowText().color().value()
			 << "Factor" << factor;
	red = QBrush(QColor(255, 0, 0).lighter(factor));
	yellow = QBrush(QColor(255, 255, 0).lighter(factor));
	cyan = QBrush(QColor(127, 255, 212).lighter(factor));
}

QString pki_base::base64UrlEncode(const BIGNUM *bn, int bits) const
{
	BioByteArray big(bn, bits);
	return big.base64UrlEncode();
}

void pki_base::exportToJWK(XFile &file, const pki_export *xport) const
{
	QJsonObject json;
	fillJWK(json, xport);
	file.write(QJsonDocument(json).toJson());
}