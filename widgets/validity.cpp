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

#include "validity.h"

#include <qcombobox.h>
#include <qlineedit.h>
#include <qvalidator.h>
#include <qlayout.h>
#include <qtooltip.h>
#include <qwhatsthis.h>
#include <qpushbutton.h>
#include <qfontmetrics.h>
#include <qlabel.h>
#include "lib/asn1time.h"

Validity::Validity( QWidget* parent,  const char* name )
    : QWidget( parent, name )
{
    int charw = this->fontMetrics().width('0');
    int space = 10;
    
#define CHAR_W(x) (charw * (x) + space)
    
    QStringList months;
    months << tr("Jan") << tr("Feb") << tr("Mar") << tr("Apr") 
	   << tr("May") << tr("Jun") << tr("Jul") << tr("Aug")
	   << tr("Sep") << tr("Oct") << tr("Nov") << tr("Dec");
    
    if ( !name )
	setName( "Validity" );
    ValidityLayout = new QHBoxLayout( this ); 
    ValidityLayout->setSpacing( 6 );
    ValidityLayout->setMargin( 0 );

    Mon = new QComboBox( FALSE, this, "Mon" );
    Mon->insertStringList(months);
    
    Year = new QLineEdit( this, "Year" );
    Year->setMinimumWidth(CHAR_W(4));
    Year->setValidator( new QIntValidator(1000, 9999, this));
    
    Day = new QLineEdit( this, "Day" );
    Day->setMinimumWidth(CHAR_W(2));
    Day->setValidator( new QIntValidator(1, 31, this));
    
    Hour = new QLineEdit( this, "Hour" );
    Hour->setMinimumWidth(CHAR_W(2));
    Hour->setValidator( new QIntValidator(1, 23, this));
    
    Min = new QLineEdit( this, "Min" );
    Min->setMinimumWidth(CHAR_W(2));
    Min->setValidator( new QIntValidator(1, 59, this));
    
    Sec = new QLineEdit( this, "Sec" );
    Sec->setMinimumWidth(CHAR_W(2));
    Sec->setValidator( new QIntValidator(1, 59, this));
    
    bnNow = new QPushButton(this, "now" );
    bnNow->setMaximumWidth(this->fontMetrics().width("Now") + 16);
    bnNow->setText(tr("Now"));
    
    l1 = new QLabel(":", this, "l1");
    l2 = new QLabel(":", this, "l2");

    ValidityLayout->addWidget( Day );
    ValidityLayout->addWidget( Mon );
    ValidityLayout->addWidget( Year );
    ValidityLayout->addWidget( Hour );
    ValidityLayout->addWidget( l1 );
    ValidityLayout->addWidget( Min );
    ValidityLayout->addWidget( l2 );
    ValidityLayout->addWidget( Sec );
    ValidityLayout->addWidget( bnNow );

    connect( bnNow, SIGNAL(clicked()), this, SLOT(setNow()));
}

Validity::~Validity()
{
    // no need to delete child widgets, Qt does it all for us
}

a1time Validity::getDate() const
{
	a1time date;
	date.set(Year->text().toInt(),
		Mon->currentItem() + 1,
		Day->text().toInt(), 
		Hour->text().toInt(),
		Min->text().toInt(),
		Sec->text().toInt()
		);
	return date;
}

void Validity::setDate(const a1time &a, int midnight)
{
	int y, m, d, h, min, s, g;
	QString S;
	
	a.ymdg(&y, &m, &d, &h, &min, &s, &g);
	
	if (midnight == 1) {
		h=0; min=0; s=0;
	}
	if (midnight == -1) {
		h=23; min=59; s=59;
	}

	Year->setText(S.sprintf("%02d",y));
	Mon->setCurrentItem(m-1);
	Day->setText(S.sprintf("%02d",d));
	Hour->setText(S.sprintf("%02d",h));
	Min->setText(S.sprintf("%02d",min));
	Sec->setText(S.sprintf("%02d",s));
}

void Validity::setNow()
{
	a1time a;
	setDate(a.now());
}
		
