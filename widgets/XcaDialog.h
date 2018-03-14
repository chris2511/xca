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

		QPixmap *icon = NULL;
		switch (type) {
		case asym_key:   icon = MainWindow::keyImg; break;
		case x509_req:   icon = MainWindow::csrImg; break;
		case x509:       icon = MainWindow::certImg; break;
		case revocation: icon = MainWindow::revImg; break;
		case tmpl:       icon = MainWindow::tempImg; break;
		case smartCard:  icon = MainWindow::scardImg; break;
		default: break;
		}
		if (icon)
			image->setPixmap(*icon);
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
	void aboutDialog(QPixmap *lefticon)
	{
		QPixmap left = *lefticon;
		title->setPixmap(left.scaledToHeight(title->height()));
		noSpacer();
		resize(560, 400);
		buttonBox->setStandardButtons(QDialogButtonBox::Ok);
		buttonBox->centerButtons();
	}
};

#endif
