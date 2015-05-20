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

enum revCol { Cnumber, Cserial, Cdate, Creason, CiDate, Cmax };

class revListItem : public QTreeWidgetItem
{
    public:
	revListItem(QTreeWidget *w) : QTreeWidgetItem(w) { };
	bool operator < (const QTreeWidgetItem &other) const
	{
		int col = treeWidget()->sortColumn();
		switch (col) {
		case Cserial: {
			a1int ithis, iother;
			ithis.setHex(text(Cserial));
			iother.setHex(other.text(Cserial));
			return ithis < iother;
		}
		case Cnumber:
			return text(Cnumber).toLong() <
				other.text(Cnumber).toLong();
		default:
			return QTreeWidgetItem::operator < (other);
		}
	}
};

static void addRevItem(QTreeWidget *certList, const x509rev &revit,
			int no, const pki_x509 *iss)
{
	revListItem *current;
	pki_x509 *rev;
	a1time a;
	rev = iss ? iss->getBySerial(revit.getSerial()) : NULL;
	current = new revListItem(certList);
	if (rev != NULL) {
		for (int i = 0; i < Cmax; i++)
			current->setToolTip(i, rev->getIntName());
	}
	current->setText(Cnumber, QString("%1").arg(no));
	current->setText(Cserial, revit.getSerial().toHex());
	current->setText(Cdate, revit.getDate().toSortable());
	current->setText(Creason, revit.getReason());

	current->setTextAlignment(Cnumber, Qt::AlignRight);
	current->setTextAlignment(Cserial, Qt::AlignRight);

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

	sl << tr("No.") << tr("Serial") << tr("Revocation") << tr("Reason") <<
		tr("Invalidation");

	cols = sl.size();
	certList->setColumnCount(cols);
	certList->setHeaderLabels(sl);
	certList->setItemsExpandable(false);
	certList->setRootIsDecorated(false);
	certList->sortItems(Cnumber, Qt::AscendingOrder);

	i=1;
	foreach(x509rev revit, revList) {
		addRevItem(certList, revit, i++, iss);
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
	Revocation *revoke = new Revocation(this, QModelIndexList());
        if (revoke->exec()) {
		x509rev revit = revoke->getRevocation();
		revList << revit;
		addRevItem(certList, revit, revList.size(), issuer);
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

Revocation::Revocation(QWidget *w, QModelIndexList indexes) : QDialog(w)
{
	setupUi(this);
	setWindowTitle(XCA_TITLE);
	reason->addItems(x509rev::crlreasons());
	invalid->setNow();

	if (indexes.size() > 1) {
		QList<a1int> serials;
		QStringList sl;
		serial->setText(QString("Batch revocation of %1 Certificates").
				arg(indexes.size()));
		foreach(QModelIndex idx, indexes) {
			pki_x509 *cert = static_cast<pki_x509*>
				(idx.internalPointer());
			serials << cert->getSerial();
		}
		qSort(serials.begin(), serials.end());
		foreach(a1int a, serials)
			sl << a.toHex();
		serial->setToolTip(sl.join("\n"));
		serial->setEnabled(false);
	} else if (indexes.size() == 1) {
		pki_x509 *cert = static_cast<pki_x509*>
				(indexes[0].internalPointer());
		serial->setText(cert->getSerial().toHex());
		serial->setEnabled(false);
	} else {
		serial->setValidator(
			new QRegExpValidator(QRegExp("[A-Fa-f0-9]+"), serial));
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
