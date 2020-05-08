/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "lib/func.h"
#include "lib/base.h"
#include "lib/Passwd.h"
#include "lib/exception.h"
#include "XcaWarning.h"
#include "PwDialog.h"
#include <QLabel>
#include <QMessageBox>

static int hex2bin(QString &x, Passwd *final)
{
	bool ok = false;
	int len = x.length();

	if (len % 2)
		return -1;
	len /= 2;

	final->clear();

	for (int i=0; i<len; i++) {
		final->append((x.mid(i*2, 2).toInt(&ok, 16)) & 0xff);
		if (!ok)
			return -1;
	}
	return len;
}

enum open_result PwDialog::execute(pass_info *p, Passwd *passwd,
					bool write, bool abort)
{
#if !defined(Q_OS_WIN32)
	if (!IS_GUI_APP) {
		console_write(stdout,
			QString(COL_CYAN "%1\n" COL_LRED "%2:" COL_RESET)
				.arg(p->getDescription())
				.arg(tr("Password")).toUtf8());
		*passwd = readPass();
		return pw_ok;
	}
#endif
	PwDialog *dlg = new PwDialog(p, write);
	if (abort)
		dlg->addAbortButton();
	enum open_result result = (enum open_result)dlg->exec();
	*passwd = dlg->getPass();
	delete dlg;
	if (result == pw_exit)
		throw pw_exit;
	return result;
}

int PwDialog::pwCallback(char *buf, int size, int rwflag, void *userdata)
{
	Passwd passwd;
	enum open_result result;
	pass_info *p = static_cast<pass_info *>(userdata);

	result = PwDialog::execute(p, &passwd, rwflag, false);

	size = MIN(size, passwd.size());
	memcpy(buf, passwd.constData(), size);
	p->setResult(result);
	return result == pw_ok ? size : 0;
}

PwDialog::PwDialog(pass_info *p, bool write)
	:QDialog(p->getWidget())
{
	pi = p;
	setupUi(this);
	image->setPixmap(QPixmap(pi->getImage()));
	description->setText(pi->getDescription());
	title->setText(pi->getType());
	if (!pi->getTitle().isEmpty())
		setWindowTitle(pi->getTitle());
	else
		setWindowTitle(XCA_TITLE);
	if (pi->getType() != "PIN")
		takeHex->hide();
	setRW(write);
}

void PwDialog::setRW(bool write)
{
	wrDialog = write;
	if (write) {
		label->setText(pi->getType());
		repeatLabel->setText(tr("Repeat %1").arg(pi->getType()));
		label->show();
		passA->show();
	} else {
		repeatLabel->setText(pi->getType());
		label->hide();
		passA->hide();
	}
}

void PwDialog::accept()
{
	if (wrDialog && (passA->text() != passB->text())) {
		XCA_WARN(tr("%1 mismatch").arg(pi->getType()));
		return;
	}
	QString pw = passB->text();
	if (takeHex->isChecked()) {
		int ret = hex2bin(pw, &final);
		if (ret == -1) {
			XCA_WARN(tr("Hex password must only contain the characters '0' - '9' and 'a' - 'f' and it must consist of an even number of characters"));
			return;
		}
	} else {
		final = pw.toLatin1();
	}
	QDialog::accept();
}

void PwDialog::buttonPress(QAbstractButton *but)
{
	qDebug() << "buttonBox->standardButton(but)" << buttonBox->buttonRole(but) << QDialogButtonBox::DestructiveRole;
	switch (buttonBox->buttonRole(but)) {
	case QDialogButtonBox::AcceptRole:
		accept();
		break;
	case QDialogButtonBox::RejectRole:
		reject();
		break;
	case QDialogButtonBox::ResetRole:
		done(pw_exit);
		break;
	default:
		break;
	}
}

void PwDialog::addAbortButton()
{
	buttonBox->addButton(tr("Exit"), QDialogButtonBox::ResetRole);
}
