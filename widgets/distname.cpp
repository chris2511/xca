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
 * 	written by Eric Young (eay@cryptsoft.com)"
 *
 *	http://www.sleepycat.com
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

#include <qcombobox.h>
#include <qlabel.h>
#include <qlineedit.h>
#include <qpushbutton.h>
#include <qlayout.h>
#include <qvariant.h>
#include <qtooltip.h>
#include <qwhatsthis.h>
#include "lib/x509name.h"
#include <iostream>

DistName::DistName( QWidget* parent,  const char* name )
    : QWidget( parent, name )
{
	if ( !name )
		setName( "DistName" );
	
	DistNameLayout = new QGridLayout(this); 
	DistNameLayout->setAlignment( Qt::AlignTop );
	DistNameLayout->setSpacing( 6 );
	DistNameLayout->setMargin( 11 );
}

void DistName::setX509name(const x509name &n)
{
	QLabel *lb;
	QLineEdit *le;
	QStringList sl;
	for (int i=0; i<n.entryCount(); i++) {
		lb = new QLabel( this );
		le = new QLineEdit( this );
		sl = n.entryList(i);
		lb->setText(sl[1]);
		if (lb->text().isEmpty())
			lb->setText(sl[0]);
		le->setText(sl[2]);
		le->setReadOnly(true);
		DistNameLayout->addWidget( lb, i, 0 );
		DistNameLayout->addWidget( le, i, 1 );
	}
}

DistName::~DistName()
{
    // no need to delete child widgets, Qt does it all for us
}

void DistName::resizeEvent( QResizeEvent *e)
{
	QWidget::resizeEvent(e);
	//cerr << "W size:" << size().height() << " -- " << size().width() <<endl;
	//cerr << "max:" << maximumSize().height() << " -- " << maximumSize().width() <<endl;
	//cerr << "L.max:" << DistNameLayout->maximumSize().height() << " -- " << DistNameLayout->maximumSize().width() <<endl;
}

/*******************************************************************/

myGridlayout::myGridlayout(QWidget * parent, int nRows = 1, int nCols = 1, int margin = 0, int space = -1, const char * name = 0) 
	:QGridLayout(parent, nRows, nCols, margin, space, name)
{
}

QSize myGridlayout::maximumSize() const
{
	QSize s = QGridLayout::maximumSize();
	s.setHeight(32767);
	return s;
};				

