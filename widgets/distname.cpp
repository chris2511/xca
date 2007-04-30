/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "distname.h"

#include <qlabel.h>
#include <qpushbutton.h>
#include <qlineedit.h>
#include "lib/x509name.h"
#include "lib/base.h"
#include "widgets/clicklabel.h"

DistName::DistName(QWidget* parent)
    : QWidget(parent)
{
	QHBoxLayout *h = new QHBoxLayout();
	QVBoxLayout *v = new QVBoxLayout(this);
	QLabel *l = new QLabel(QString("RFC 2253:"), this);
	lineEdit = new QLineEdit(this);

	DistNameLayout = new QGridLayout();
	DistNameLayout->setAlignment( Qt::AlignTop );
	DistNameLayout->setSpacing(6);
	DistNameLayout->setMargin(11);
	v->setSpacing(6);
	v->setMargin(11);
	v->addLayout(DistNameLayout);
	v->addLayout(h);

	v->setSpacing(6);
	h->addWidget(l);
	h->addWidget(lineEdit);
	lineEdit->setReadOnly(true);
}

void DistName::setX509name(const x509name &n)
{
	QLabel *l1, *l2;
	QStringList sl;
	for (int i=0; i<n.entryCount(); i++) {
		l1 = new QLabel( this );
		l2 = new CopyLabel( this );
		sl = n.entryList(i);
		l1->setText(sl[1]);
		if (l1->text().isEmpty())
			l1->setText(sl[0]);
		l2->setText(sl[2]);
		l2->setFrameShape(QFrame::Panel);
		l2->setFrameShadow(QFrame::Sunken);

		l1->setToolTip(sl[0]);
		l2->setToolTip(sl[3]);

		DistNameLayout->addWidget( l1, i, 0 );
		DistNameLayout->addWidget( l2, i, 1 );
	}
	lineEdit->setText(n.oneLine(XN_FLAG_RFC2253));
	lineEdit->setCursorPosition(0);
	updateGeometry();
}

DistName::~DistName()
{
    // no need to delete child widgets, Qt does it all for us
}

void DistName::resizeEvent( QResizeEvent *e)
{
	QWidget::resizeEvent(e);
}
