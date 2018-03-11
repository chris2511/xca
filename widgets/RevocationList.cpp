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
			return a1int(text(Cserial)) <
				a1int(other.text(Cserial));
		}
		case Cnumber:
			return text(Cnumber).toLong() <
				other.text(Cnumber).toLong();
		default:
			return QTreeWidgetItem::operator < (other);
		}
	}
};

static void setup_revRevItem(QTreeWidgetItem *item, const x509rev &revit,
			const pki_x509 *iss)
{
	pki_x509 *rev = iss ? iss->getBySerial(revit.getSerial()) : NULL;
	if (rev != NULL) {
		for (int i = 0; i < Cmax; i++)
			item->setToolTip(i, rev->getIntName());
	}
	item->setText(Cserial, revit.getSerial());
	item->setText(Cdate, revit.getDate().toSortable());
	item->setText(Creason, revit.getReason());

	item->setTextAlignment(Cnumber, Qt::AlignRight);
	item->setTextAlignment(Cserial, Qt::AlignRight);

	a1time a = revit.getInvalDate();
	if (!a.isUndefined())
		item->setText(CiDate, a.toSortable());
}

static void addRevItem(QTreeWidget *certList, const x509rev &revit,
			int no, const pki_x509 *iss)
{
	revListItem *current;
	current = new revListItem(certList);
	current->setText(Cnumber, QString("%1").arg(no));
	setup_revRevItem(current, revit, iss);
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
	certList->setSelectionBehavior(QAbstractItemView::SelectRows);
	certList->setSelectionMode(QAbstractItemView::ExtendedSelection);
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

	connect(certList, SIGNAL(doubleClicked(const QModelIndex &)),
		this, SLOT(on_editRev_clicked(const QModelIndex &)));
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

	if (!current)
		return;
	idx = certList->indexOfTopLevelItem(current);
	certList->takeTopLevelItem(idx);
	rev.setSerial(a1int(current->text(Cserial)));
	idx = revList.indexOf(rev);
        if (idx != -1)
                revList.takeAt(idx);
}

void RevocationList::on_editRev_clicked()
{
	QTreeWidgetItem *current = certList->currentItem();
	x509rev rev;
	int idx;

	if (!current)
		return;

	rev.setSerial(a1int(current->text(Cserial)));
	idx = revList.indexOf(rev);
        if (idx == -1)
		return;

	rev = revList[idx];

	Revocation *revoke = new Revocation(this, QModelIndexList());
	revoke->setRevocation(rev);
        if (revoke->exec()) {
		a1time a1 = rev.getDate();
		rev = revoke->getRevocation();
		rev.setDate(a1);
		revList[idx] = rev;
		setup_revRevItem(current, rev, issuer);
	}
	delete revoke;
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
			sl << a;
		serial->setToolTip(sl.join("\n"));
		serial->setEnabled(false);
	} else if (indexes.size() == 1) {
		pki_x509 *cert = static_cast<pki_x509*>
				(indexes[0].internalPointer());
		serial->setText(cert->getSerial());
		serial->setEnabled(false);
	} else {
		serial->setValidator(
			new QRegExpValidator(QRegExp("[A-Fa-f0-9]+"), serial));
	}
}

x509rev Revocation::getRevocation()
{
	x509rev r;

	r.setSerial(a1int(serial->text()));
	r.setInvalDate(invalid->getDate());
	r.setDate(a1time());
	r.setCrlNo(0);
	r.setReason(reason->currentText());
	return r;
}

void Revocation::setRevocation(x509rev r)
{
	serial->setText(r.getSerial());
	invalid->setDate(r.getInvalDate());
	int i = reason->findText(r.getReason());
	if (i == -1)
		i = 0;
	reason->setCurrentIndex(i);
}
