/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2012 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "CrlDetail.h"
#include "MainWindow.h"
#include "lib/pki_crl.h"
#include "widgets/distname.h"
#include "widgets/clicklabel.h"
#include "widgets/RevocationList.h"
#include <QLabel>
#include <QTextEdit>
#include <QLineEdit>

CrlDetail::CrlDetail(MainWindow *mainwin)
	:QDialog(mainwin)
{
	mw = mainwin;
	setupUi(this);
	setWindowTitle(tr(XCA_TITLE));

	image->setPixmap(*MainWindow::revImg);
}

void CrlDetail::setCrl(pki_crl *crl)
{
	pki_x509 *iss;
	x509v3ext e1, e2;

	iss = crl->getIssuer();
	signCheck->disableToolTip();
	signCheck->setClickText(crl->getSigAlg());
	if (iss != NULL) {
		issuerIntName->setText(iss->getIntName());
		issuerIntName->setClickText(iss->getSqlItemId().toString());
		issuerIntName->setGreen();
		if (crl->verify(iss)) {
			signCheck->setText(crl->getSigAlg());
			signCheck->setGreen();
		} else {
			signCheck->setText(tr("Failed"));
			signCheck->setRed();
		}
	} else {
		issuerIntName->setText(tr("Unknown signer"));
		issuerIntName->setDisabled(true);
		issuerIntName->disableToolTip();
		signCheck->setText(tr("Verification not possible"));
		signCheck->setDisabled(true);
	}

	connect(signCheck, SIGNAL(doubleClicked(QString)),
		MainWindow::getResolver(), SLOT(searchOid(QString)));

	descr->setText(crl->getIntName());
	lUpdate->setText(crl->getLastUpdate().toPretty());
	lUpdate->setToolTip(crl->getLastUpdate().toPrettyGMT());
	nUpdate->setText(crl->getNextUpdate().toPretty());
	nUpdate->setToolTip(crl->getNextUpdate().toPrettyGMT());
	version->setText((++crl->getVersion()).toHex());

	issuer->setX509name(crl->getSubject());

	RevocationList::setupRevocationView(certList, crl->getRevList(), iss);

	v3extensions->document()->setHtml(crl->printV3ext());

	comment->setPlainText(crl->getComment());
}
