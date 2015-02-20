/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "PwDialog.h"
#include "lib/base.h"
#include "lib/Passwd.h"
#include "widgets/MainWindow.h"
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

int PwDialog::execute(pass_info *p, Passwd *passwd, bool write, bool abort)
{
	PwDialog *dlg;
	int ret;
	dlg = new PwDialog(p, write);
	if (abort)
		dlg->addAbortButton();
        ret = dlg->exec();
	*passwd = dlg->getPass();
	delete dlg;
	return ret;
}

int PwDialog::pwCallback(char *buf, int size, int rwflag, void *userdata)
{
	int ret;

	pass_info *p = (pass_info *)userdata;
	PwDialog *dlg = new PwDialog(p, rwflag);

	ret = dlg->exec();
	QByteArray pw = dlg->getPass();
	size = MIN(size, pw.size());
	memcpy(buf, pw.constData(), size);
	delete dlg;
	return ret == 1 ? size : 0;
}

PwDialog::PwDialog(pass_info *p, bool write)
	:QDialog(p->getWidget())
{
	pi = p;
	setupUi(this);
	image->setPixmap(pi->getImage());
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
		XCA_WARN(tr("%1 missmatch").arg(pi->getType()));
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
	switch (buttonBox->standardButton(but)) {
	case QDialogButtonBox::Ok:
		accept();
		break;
	case QDialogButtonBox::Cancel:
		reject();
		break;
	case QDialogButtonBox::Abort:
	default:
		done(2);
	}
}

void PwDialog::addAbortButton()
{
	buttonBox->addButton(tr("E&xit"), QDialogButtonBox::ResetRole);
}
