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
#include "lib/asn1time.h"

Validity::Validity( QWidget* parent,  const char* name )
    : QWidget( parent, name )
{
    QStringList months, days;
    months << tr("Jan") << tr("Feb") << tr("Mar") << tr("Apr") 
	   << tr("Mai") << tr("Jun") << tr("Jul") << tr("Aug")
	   << tr("Sep") << tr("Okt") << tr("Nov") << tr("Dez");
    for (int i=1; i<32; i++)
	    days += QString::number(i);

    if ( !name )
	setName( "Validity" );
    ValidityLayout = new QHBoxLayout( this ); 
    ValidityLayout->setSpacing( 6 );
    ValidityLayout->setMargin( 0 );

    Day = new QComboBox( FALSE, this, "Day" );
    Mon = new QComboBox( FALSE, this, "Mon" );
    Year = new QLineEdit( this, "Year" );
    Year->setMaximumWidth(64);
    Year->setValidator( new QIntValidator(1000, 9999, this));
    
    ValidityLayout->addWidget( Day );
    ValidityLayout->addWidget( Mon );
    ValidityLayout->addWidget( Year );

    Mon->insertStringList(months);
    Day->insertStringList(days);
}

Validity::~Validity()
{
    // no need to delete child widgets, Qt does it all for us
}

a1time Validity::getDate() const
{
	a1time date;
	date.set(Year->text().toInt(), Mon->currentItem() + 1, 
			Day->currentItem() +1, 0, 0, 0);
	return date;
}

void Validity::setDate(const a1time &a)
{
	int y, m, d, g;
	a.ymdg(&y,&m,&d,&g);
	Year->setText(QString::number(y));
	Mon->setCurrentItem(m-1);
	Day->setCurrentItem(d-1);
}

