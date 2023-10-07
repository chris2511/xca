/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2023 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QLabel>
#include <QTextEdit>
#include <QLineEdit>
#include <QDialogButtonBox>
#include <QDialog>

#include "MainWindow.h"
#include "XcaDetail.h"
#include "Help.h"
#include "ImportMulti.h"
#include "lib/pki_base.h"
#include "lib/database_model.h"

XcaDetail::XcaDetail(QWidget *w)
	: QDialog(w && w->isVisible() ? w : nullptr)
{
	importmulti = dynamic_cast<ImportMulti *>(w);
	setWindowTitle(XCA_TITLE);
	Database.connectToDbChangeEvt(this, SLOT(itemChanged(pki_base*)));
}

void XcaDetail::init(const char *helpctx, const char *img)
{
	mainwin->helpdlg->register_ctxhelp_button(this, helpctx);
	QLabel *image = findChild<QLabel*>("image");
	if (image)
		image->setPixmap(QPixmap(img));
}

void XcaDetail::itemChanged(pki_base *)
{
}

void XcaDetail::connect_pki(pki_base *p)
{
	QDialogButtonBox *buttonBox = findChild<QDialogButtonBox*>("buttonBox");
	pki = p;

	if (buttonBox && pki && pki->getSqlItemId() == QVariant()) {
		importbut = buttonBox->addButton(tr("Import"), QDialogButtonBox::ApplyRole);
		connect(importbut, SIGNAL(clicked(bool)), this, SLOT(import()));
	}
	QPushButton *but = buttonBox->button(QDialogButtonBox::Ok);
	if (but)
		connect(but, SIGNAL(clicked(bool)), this, SLOT(accept()));
}

void XcaDetail::updateNameComment()
{
	if (!pki)
		return;
	QLineEdit *descr = findChild<QLineEdit*>("descr");
	if (descr)
		pki->setIntName(descr->text());
	QTextEdit *comment = findChild<QTextEdit*>("comment");
	if (comment)
		pki->setComment(comment->toPlainText());
}

void XcaDetail::import()
{
	updateNameComment();

	qDebug() << "ImportMulti" << importmulti;
	if (pki)
		pki = importmulti ? importmulti->import(pki) : Database.insert(pki);

	if (pki && !Settings["suppress_messages"])
		XCA_INFO(pki->getMsg(pki_base::msg_import).arg(pki->getIntName()));

	QDialogButtonBox *buttonBox = findChild<QDialogButtonBox*>("buttonBox");
	if (buttonBox && !pki && importbut) {
		buttonBox->removeButton(importbut);
		importbut = nullptr;
		QLineEdit *descr = findChild<QLineEdit*>("descr");
		if (descr)
			descr->setReadOnly(true);
		QTextEdit *comment = findChild<QTextEdit*>("comment");
		if (comment)
			comment->setReadOnly(true);
	}
}

void XcaDetail::accept()
{
	db_base *db = Database.modelForPki(pki);
	updateNameComment();
	if (pki && pki->getSqlItemId().isValid() && db)
		db->updateItem(pki);
	QDialog::accept();
}
