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
#include <QValidator>
#include "XcaWarning.h"
#include "lib/exception.h"
#include "lib/ipvalidator.h"
#include "lib/x509v3ext.h"

#include <openssl/err.h>


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
	if (n != NID_subject_alt_name)
		copy_cn->hide();
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
	for (i=0; i< sl.count(); i++) {
		if (sl[i] == "DNS:copycn" && nid == NID_subject_alt_name)
			copy_cn->setChecked(true);
		else
			addEntry(sl[i]);
	}
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
		tt = tr("A registered ID: OBJECT IDENTIFIER");
		QRegExp rx("[a-zA-Z0-9.]+");
		v = new QRegExpValidator(rx, this);
	} else if (s == "URI") {
		tt = tr("A uniform resource indicator");
		QRegExp rx("[a-z][a-z0-9\\.\\+\\-]*://.*");
                v = new QRegExpValidator(rx, this);
	} else if (s == "DNS") {
		if (nid == NID_subject_alt_name)
			tt = tr("A DNS domain name or 'copycn'");
		else
			tt = tr("A DNS domain name");
	} else if (s == "IP") {
		tt = tr("An IP address");
		v = new ipValidator();
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
	if (copy_cn->isChecked())
		str << "DNS:copycn";

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
