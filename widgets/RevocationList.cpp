/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "RevocationList.h"
#include "MainWindow.h"
#include "lib/asn1int.h"
#include "lib/pki_x509.h"

enum revCol { Cserial, Cdate, Creason, CiDate };

static void addRevItem(QTreeWidget *certList, const x509rev &revit,
			const pki_x509 *iss)
{
	QTreeWidgetItem *current;
	pki_x509 *rev;
	a1time a;
	rev = iss->getBySerial(revit.getSerial());
	current = new QTreeWidgetItem(certList);
	if (rev != NULL) {
		current->setToolTip(Cserial, rev->getIntName() );
	}
	current->setText(Cserial, revit.getSerial().toHex()) ;
	current->setText(Cdate, revit.getDate().toSortable());
	current->setText(Creason, revit.getReason());
	a = revit.getInvalDate();
	if (!a.isUndefined())
		current->setText(CiDate, a.toSortable());
}

void RevocationList::setupRevocationView(QTreeWidget *certList,
			const x509revList &revList, const pki_x509 *iss)
{
	QStringList sl;
	int cols, i;

	certList->clear();

	sl << tr("Serial") << tr("Revocation") << tr("Reason") <<
		tr("Invalidation");

	cols = sl.size();
	certList->setColumnCount(cols);
	certList->setHeaderLabels(sl);
	certList->setItemsExpandable(false);
	certList->setRootIsDecorated(false);

	foreach(x509rev revit, revList) {
		addRevItem(certList, revit, iss);
	}
	for (i=0; i<cols; i++)
		certList->resizeColumnToContents(i);
	certList->setSortingEnabled(true);
}

RevocationList::RevocationList(QWidget *w) : QDialog(w)
{
	QPushButton *genCrl;
	setupUi(this);
	setWindowTitle(XCA_TITLE);
	image->setPixmap(*MainWindow::revImg);

	genCrl = buttonBox->addButton(tr("Generate CRL"),
				QDialogButtonBox::ActionRole);
	connect(genCrl, SIGNAL(clicked(void)), this, SLOT(gencrl(void)));
}

void RevocationList::gencrl(void)
{
	issuer->setRevocations(getRevList());
	emit genCRL(issuer);
}

void RevocationList::setRevList(const x509revList &rl, pki_x509 *iss)
{
	issuer = iss;
	revList = rl;
	setupRevocationView(certList, revList, issuer);
}

const x509revList &RevocationList::getRevList()
{
	return revList;
}

void RevocationList::on_addRev_clicked(void)
{
	Revocation *revoke = new Revocation(this, NULL);
        if (revoke->exec()) {
		x509rev revit = revoke->getRevocation();
		revList << revit;
		addRevItem(certList, revit, issuer);
	}
}

void RevocationList::on_delRev_clicked(void)
{
	QTreeWidgetItem *current = certList->currentItem();
	x509rev rev;
	int idx;
	a1int a1_serial;

	if (!current)
		return;
	idx = certList->indexOfTopLevelItem(current);
	certList->takeTopLevelItem(idx);
	a1_serial.setHex(current->text(Cserial));
	rev.setSerial(a1_serial);
	idx = revList.indexOf(rev);
        if (idx != -1)
                revList.takeAt(idx);
}

Revocation::Revocation(QWidget *w, pki_x509 *r) : QDialog(w)
{
	setupUi(this);
	setWindowTitle(XCA_TITLE);
	reason->addItems(x509rev::crlreasons());
	invalid->setNow();
	if (r) {
		serial->setText(r->getSerial().toHex());
		serial->setEnabled(false);
	}
}

x509rev Revocation::getRevocation()
{
	x509rev r;
	a1int i;

	i.setHex(serial->text());
	r.setSerial(i);
	r.setDate(a1time::now());
	r.setInvalDate(invalid->getDate());
	r.setReason(reason->currentText());
	return r;
}
