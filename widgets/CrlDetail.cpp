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
#include <QtGui/QLabel>
#include <QtGui/QTextEdit>
#include <QtGui/QLineEdit>

CrlDetail::CrlDetail(MainWindow *mainwin)
	:QDialog(mainwin)
{
	mw = mainwin;
	setupUi(this);
	setWindowTitle(tr(XCA_TITLE));

	certList->clear();
	certList->setColumnCount(3);

	QStringList sl;
	sl << tr("Name") << tr("Serial") << tr("Revocation") << tr("Reason") <<
		tr("Invalidation");
	certList->setHeaderLabels(sl);

	image->setPixmap(*MainWindow::revImg);
	descr->setReadOnly(true);
}

void CrlDetail::setCrl(pki_crl *crl)
{
	int numc, i;
	pki_x509 *iss, *rev;
	x509rev revit;
	x509v3ext e1, e2;
	QStringList sl;

	iss = crl->getIssuer();
	signCheck->disableToolTip();
	if (iss != NULL) {
		issuerIntName->setText(iss->getIntName());
		issuerIntName->setGreen();
		pki_key *key = iss->getPubKey();
		if (crl->verify(key)) {
			signCheck->setText(crl->getSigAlg());
			signCheck->setGreen();
		} else {
			signCheck->setText(tr("Failed"));
			signCheck->setRed();
		}
		if (key)
			delete key;
	} else {
		issuerIntName->setText(tr("Unknown signer"));
		issuerIntName->setDisabled(true);
		issuerIntName->disableToolTip();
		signCheck->setText(tr("Verification not possible"));
		signCheck->setDisabled(true);
	}

	descr->setText(crl->getIntName());
	lUpdate->setText(crl->getLastUpdate().toPretty());
	lUpdate->setToolTip(crl->getLastUpdate().toPrettyGMT());
	nUpdate->setText(crl->getNextUpdate().toPretty());
	nUpdate->setToolTip(crl->getNextUpdate().toPrettyGMT());
	version->setText((++crl->getVersion()).toHex());

	issuer->setX509name(crl->getSubject());

	numc = crl->numRev();
	for (i=0; i<numc; i++) {
		QTreeWidgetItem *current;
		a1time a;
		revit = crl->getRev(i);
		rev = mw->certs->getByIssSerial(iss, revit.getSerial());
		certList->setColumnCount(5);
		current = new QTreeWidgetItem(certList);
		if (rev != NULL) {
			current->setText(0, rev->getIntName() );
		} else {
			current->setText(0, tr("Unknown certificate"));
		}
		current->setIcon(0, *pki_x509::icon[2]);
		current->setText(1, revit.getSerial().toHex()) ;
		current->setText(2, revit.getDate().toSortable());
		current->setText(3, revit.getReason());
		a = revit.getInvalDate();
		if (!a.isUndefined())
			current->setText(4, a.toSortable());
	}
	for (i=0; i<5; i++)
		certList->resizeColumnToContents(i);
	certList->setSortingEnabled(true);
	v3extensions->document()->setHtml(crl->printV3ext());
}
