/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QPixmap>
#include "XcaDialog.h"
#include "MainWindow.h"
#include "Help.h"

// index = enum pki_type
static const char * const PixmapMap[] = {
  "" ":keyImg", ":csrImg", ":certImg", ":revImg", ":tempImg", "", ":scardImg",
};

XcaDialog::XcaDialog(QWidget *parent, enum pki_type type, QWidget *w,
			const QString &t, const QString &desc,
			const QString &help_ctx)
	 : QDialog(parent ? parent : mainwin)
{
	setupUi(this);
	setWindowTitle(XCA_TITLE);
	image->setPixmap(QPixmap(PixmapMap[type]));
	content->addWidget(w);
	mainwin->helpdlg->register_ctxhelp_button(this, help_ctx);

	widg = w;
	title->setText(t);
	if (desc.isEmpty()) {
		verticalLayout->removeWidget(description);
		delete description;
	} else {
		description->setText(desc);
	}
}

void XcaDialog::noSpacer()
{
	verticalLayout->removeItem(topSpacer);
	verticalLayout->removeItem(bottomSpacer);
	delete topSpacer;
	delete bottomSpacer;
	if (widg)
		widg->setSizePolicy(QSizePolicy::Expanding,
					QSizePolicy::Expanding);
}

void XcaDialog::aboutDialog(const QPixmap &left)
{
	title->setPixmap(left.scaledToHeight(title->height()));
	noSpacer();
	resize(560, 400);
	buttonBox->setStandardButtons(QDialogButtonBox::Ok);
	buttonBox->centerButtons();
}
