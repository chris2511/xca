/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "distname.h"

#include <QLabel>
#include <QPushButton>
#include <QLineEdit>
#include "lib/x509name.h"
#include "lib/db_x509super.h"
#include "lib/base.h"
#include "clicklabel.h"
#include "MainWindow.h"

DistName::DistName(QWidget* parent)
    : QWidget(parent)
{
	DistNameLayout = new QGridLayout();
	DistNameLayout->setAlignment(Qt::AlignTop);
	DistNameLayout->setSpacing(6);
	DistNameLayout->setMargin(11);

	QGridLayout *g = new QGridLayout();
	g->setAlignment(Qt::AlignTop);
	g->setSpacing(6);
	g->setMargin(11);

	QVBoxLayout *v = new QVBoxLayout(this);
	v->setSpacing(6);
	v->setMargin(11);
	v->addLayout(DistNameLayout);
	v->addStretch();
	v->addLayout(g);

	rfc2253 = new QLineEdit(this);
	rfc2253->setReadOnly(true);
	g->addWidget(new QLabel(QString("RFC 2253:"), this), 0, 0);
	g->addWidget(rfc2253, 0, 1);

	namehash = new QLineEdit(this);
	namehash->setReadOnly(true);
	g->addWidget(new QLabel(QString("Hash:"), this), 1, 0);
	g->addWidget(namehash, 1, 1);
}

void DistName::setX509name(const x509name &n)
{
	DoubleClickLabel *l1;
	QLabel *l2;
	QStringList sl;
	for (int i=0; i<n.entryCount(); i++) {
		QString toolt, label, trans;
		int nid = n.nid(i);
		trans = dn_translations[nid];
		sl = n.entryList(i);
		if (translate_dn && !trans.isEmpty()) {
			label = trans;
			toolt = sl[1];
		} else {
			toolt = trans;
			label = sl[1];
		}
		l1 = new DoubleClickLabel(this);
		l2 = new CopyLabel(this);
		l1->setTextFormat(Qt::PlainText);
		l1->setText(label);
		l1->setClickText(sl[1]);
		if (l1->text().isEmpty())
			l1->setText(sl[0]);
		l2->setText(sl[2]);

		l1->setToolTip(QString("[%1] %2").arg(sl[0]).arg(toolt));
		l2->setToolTip(sl[3]);

		connect(l1, SIGNAL(doubleClicked(QString)),
			MainWindow::getResolver(), SLOT(searchOid(QString)));

		DistNameLayout->addWidget(l1, i, 0);
		DistNameLayout->addWidget(l2, i, 1);
	}
	rfc2253->setText(n.oneLine(XN_FLAG_RFC2253));
	rfc2253->setCursorPosition(0);
	namehash->setText(n.hash());
	updateGeometry();
}
