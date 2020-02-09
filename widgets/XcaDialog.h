/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __XCADIALOG_H
#define __XCADIALOG_H

#include <QList>
#include <QDialog>
#include "ui_XcaDialog.h"
#include "lib/db.h"
#include "MainWindow.h"

class XcaDialog : public QDialog, public Ui::XcaDialog
{
	QWidget *widg;
    public:
	XcaDialog(QWidget *parent, enum pki_type type, QWidget *w,
		QString t, QString desc) : QDialog(parent)
	{
		setupUi(this);
		setWindowTitle(XCA_TITLE);
		QMap<enum pki_type, QString> map {
			{ asym_key,   ":keyImg" },
			{ x509_req,   ":csrImg" },
			{ x509,       ":certImg" },
			{ revocation, ":revImg" },
			{ tmpl,       ":tempImg" },
			{ smartCard,  ":scardImg" },
		};
		image->setPixmap(QPixmap(map[type]));
		content->addWidget(w);
		widg = w;
		title->setText(t);
		if (desc.isEmpty()) {
			verticalLayout->removeWidget(description);
			delete description;
		} else {
			description->setText(desc);
		}
	}
	void noSpacer()
	{
		verticalLayout->removeItem(topSpacer);
		verticalLayout->removeItem(bottomSpacer);
		delete topSpacer;
		delete bottomSpacer;
		if (widg)
			widg->setSizePolicy(QSizePolicy::Expanding,
						QSizePolicy::Expanding);
	}
	void aboutDialog(const QPixmap &left)
	{
		title->setPixmap(left.scaledToHeight(title->height()));
		noSpacer();
		resize(560, 400);
		buttonBox->setStandardButtons(QDialogButtonBox::Ok);
		buttonBox->centerButtons();
	}
};

#endif
