/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2005 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "v3ext.h"
#include <QLabel>
#include <QListWidget>
#include <QComboBox>
#include <QLineEdit>
#include <QHeaderView>
#include <QStringList>
#include <QMessageBox>
#include "MainWindow.h"
#include "lib/exception.h"


//	Complex regular expressions.

#define BYTE_DEC	"(?:25[0-5]|2[0-4]\\d|1\\d\\d|\\d{1,2})"
#define IPV4_ADDR	"(?:(?:" BYTE_DEC "\\.){3}" BYTE_DEC ")"
#define SHORT_HEX	"[0-9a-fA-F]{1,4}"
#define IPV6_FORM0	"(?:(?:" SHORT_HEX ":){7}" SHORT_HEX ")"
#define IPV6_FORM1	"(?::(?::" SHORT_HEX "){1,7})"
#define IPV6_FORM2	"(?:" SHORT_HEX ":(?::" SHORT_HEX "){1,6})"
#define IPV6_FORM3	"(?:(?:" SHORT_HEX ":){2}(?::" SHORT_HEX "){1,5})"
#define IPV6_FORM4	"(?:(?:" SHORT_HEX ":){3}(?::" SHORT_HEX "){1,4})"
#define IPV6_FORM5	"(?:(?:" SHORT_HEX ":){4}(?::" SHORT_HEX "){1,3})"
#define IPV6_FORM6	"(?:(?:" SHORT_HEX ":){5}(?::" SHORT_HEX "){1,2})"
#define IPV6_FORM7	"(?:(?:" SHORT_HEX ":){6}:" SHORT_HEX ")"
#define IPV6_FORM8	"(?:(?:" SHORT_HEX ":){7}:)"
#define IPV6_FORM9	"(?:::)"
#define IPV6_V4_0	"(?:(?:" SHORT_HEX ":){6}" IPV4_ADDR ")"
#define IPV6_V4_1	"(?::(?::" SHORT_HEX "){0,5}:" IPV4_ADDR ")"
#define IPV6_V4_2	"(?:" SHORT_HEX ":(?::" SHORT_HEX "){0,4}:" IPV4_ADDR ")"
#define IPV6_V4_3	"(?:(?:" SHORT_HEX ":){2}(?::" SHORT_HEX "){0,3}:" IPV4_ADDR ")"
#define IPV6_V4_4	"(?:(?:" SHORT_HEX ":){3}(?::" SHORT_HEX "){0,2}:" IPV4_ADDR ")"
#define IPV6_V4_5	"(?:(?:" SHORT_HEX ":){4}(?::" SHORT_HEX ")?:" IPV4_ADDR ")"
#define IPV6_V4_6	"(?:(?:" SHORT_HEX ":){5}:" IPV4_ADDR ")"
#define IPV6_ADDR	"(?:" IPV6_FORM0 "|" IPV6_FORM1 "|" IPV6_FORM2 "|"	\
						IPV6_FORM3 "|" IPV6_FORM4 "|" IPV6_FORM5 "|"	\
						IPV6_FORM6 "|" IPV6_FORM7 "|" IPV6_FORM8 "|"	\
						IPV6_FORM9 "|" IPV6_V4_0 "|" IPV6_V4_1 "|"		\
						IPV6_V4_2 "|" IPV6_V4_3 "|" IPV6_V4_4 "|"		\
						IPV6_V4_5 "|" IPV6_V4_6 ")"

v3ext::v3ext(QWidget *parent)
	:QDialog(parent)
{
	setupUi(this);
	setWindowTitle(XCA_TITLE);
	tab->horizontalHeader()->setDefaultSectionSize(80);
}

void v3ext::addInfo(QLineEdit *myle, const QStringList &sl, int n,
		X509V3_CTX *ctx)
{
	nid = n;
	le = myle;
	ext_ctx = ctx;
	tab->setKeys(sl);
	keys = sl;
	tab->setInfoLabel(infoLabel);
	connect(tab->itemDelegateForColumn(1),
		SIGNAL(setupLineEdit(const QString &, QLineEdit *)),
		this, SLOT(setupLineEdit(const QString &, QLineEdit *)));
	if (le && !le->text().trimmed().isEmpty())
		addItem(le->text());
}

void v3ext::addItem(QString list)
{
	int i;
	QStringList sl;
	sl = list.split(',');
	if (sl[0] == "critical") {
		sl.takeFirst();
		critical->setChecked(true);
	}
	for (i=0; i< sl.count(); i++)
		addEntry(sl[i]);
}

void v3ext::setupLineEdit(const QString &s, QLineEdit *l)
{
	QString tt;
	QValidator *v = NULL;

	if (s == "email") {
		if (nid == NID_subject_alt_name)
			tt = tr("An email address or 'copy'");
		else
			tt = tr("An email address");
	} else if (s == "RID") {
		tt = tr("a registered ID: OBJECT IDENTIFIER");
		QRegExp rx("[a-zA-Z0-9.]+");
		v = new QRegExpValidator(rx, this);
	} else if (s == "URI") {
		tt = tr("a uniform resource indicator");
		QRegExp rx("[a-z]+://.*");
                v = new QRegExpValidator(rx, this);
	} else if (s == "DNS") {
		tt = tr("a DNS domain name");
	} else if (s == "IP") {
		tt = tr("an IP address");
		QRegExp rx(IPV4_ADDR "|" IPV6_ADDR);
		v = new QRegExpValidator(rx, this);
	} else if (s == "otherName") {
		tt = tr("Syntax: <OID>;TYPE:text like '1.2.3.4:UTF8:name'");
		QRegExp rx("[a-zA-Z0-9.]+;.*");
		v = new QRegExpValidator(rx, this);
	} else if (s == "issuer") {
		tt = tr("No editing. Only 'copy' allowed here");
		l->setText(QString("copy"));
		l->setReadOnly(true);
		QRegExp rx("copy");
                v = new QRegExpValidator(rx, this);
	}
	l->setToolTip(tt);
	l->setValidator(v);
}

/* for one TYPE:Content String */
void v3ext::addEntry(QString line)
{
	int idx;
	QString type, value;

	line = line.trimmed();
	idx = line.indexOf(':');

	if (idx == -1) {
		value = line;
	} else {
		type = line.left(idx);
		value = line.mid(idx+1);
	}
	if (!keys.contains(type)) {
		type = keys[0];
		value = line;
	}
	tab->addRow(QStringList(type) << value);
}

QString v3ext::toString()
{
	QStringList str;
	int i, row = tab->rowCount();

	if (critical->isChecked())
		str << "critical";

	for (i=0; i<row; i++) {
		QStringList s = tab->getRow(i);
		str += s[0] + ":" +s[1];
	}
	return str.join(", ");
}

void v3ext::on_apply_clicked()
{
	__validate(false);
	if (le)
		le->setText(toString());
	accept();
}

bool v3ext::__validate(bool showSuccess)
{
	x509v3ext ext;
	QString str, error;
	validate->setFocus(Qt::OtherFocusReason);
	str = prefix + toString();
	ext.create(nid, str, ext_ctx);
	while (int i = ERR_get_error() ) {
		error += ERR_error_string(i ,NULL);
		error += "\n";
	}
	if (!error.isEmpty()) {
		XCA_WARN(tr("Validation failed:\n'%1'\n%2").
			arg(str).arg(error));
		return false;
	}
	if (showSuccess) {
		XCA_INFO(tr("Validation successful:\n'%1'").
			arg(ext.getValue()));
	}
	return true;
}

void v3ext::on_validate_clicked()
{
	__validate(true);
}
