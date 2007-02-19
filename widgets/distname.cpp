/*
 * Copyright (C) 2001 Christian Hohnstaedt.
 *
 *  All rights reserved.
 *
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *  - Neither the name of the author nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * This program links to software with different licenses from:
 *
 *	http://www.openssl.org which includes cryptographic software
 *	written by Eric Young (eay@cryptsoft.com)"
 *
 *	http://www.trolltech.com
 *
 *
 *
 * http://www.hohnstaedt.de/xca
 * email: christian@hohnstaedt.de
 *
 * $Id$
 *
 */

#include "distname.h"

#include <Qt/qlabel.h>
#include <Qt/qpushbutton.h>
#include <Qt/qlineedit.h>
#include "lib/x509name.h"
#include "lib/base.h"

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
		l2 = new QLabel( this );
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
