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
#include <qlabel.h>
#include <qlineedit.h>
#include <qpushbutton.h>
#include <qlayout.h>
#include <qvariant.h>
#include <qtooltip.h>
#include <qwhatsthis.h>
#include "lib/asn1time.h"

Validity::Validity( QWidget* parent,  const char* name )
    : QGroupBox( parent, name )
{
    QStringList months, days;
    months << tr("Jan") << tr("Feb") << tr("Mar") << tr("Apr") 
	   << tr("Mai") << tr("Jun") << tr("Jul") << tr("Aug")
	   << tr("Sep") << tr("Okt") << tr("Nov") << tr("Dez");
    for (int i=1; i<32; i++)
	    days += QString::number(i);

    if ( !name )
	setName( "Validity" );
    setTitle( tr( "Validity" ) );
    ValidityLayout = new QGridLayout( this ); 
    ValidityLayout->setSpacing( 6 );
    ValidityLayout->setMargin( 11 );

    Label1 = new QLabel( this, "Label1" );
    Label1->setText( tr( "not Before" ) );
    
    Label2 = new QLabel( this, "Label2" );
    Label2->setText( tr( "not After" ) );

    nbDay = new QComboBox( FALSE, this, "nbDay" );
    nbMon = new QComboBox( FALSE, this, "nbMon" );
    nbYear = new QLineEdit( this, "nbYear" );

    naDay = new QComboBox( FALSE, this, "naDay" );
    naMon = new QComboBox( FALSE, this, "naMon" );
    naYear = new QLineEdit( this, "naYear" );
    
    ValidityLayout->addWidget( Label1, 0, 0 );
    ValidityLayout->addWidget( nbDay, 0, 1 );
    ValidityLayout->addWidget( nbMon, 0, 2 );
    ValidityLayout->addWidget( nbYear, 0, 3 );

    ValidityLayout->addWidget( Label2, 1, 0 );
    ValidityLayout->addWidget( naDay, 1, 1 );
    ValidityLayout->addWidget( naMon, 1, 2 );
    ValidityLayout->addWidget( naYear, 1, 3 );

    
    nbMon->insertStringList(months);
    naMon->insertStringList(months);
    nbDay->insertStringList(days);
    naDay->insertStringList(days);
}

Validity::~Validity()
{
    // no need to delete child widgets, Qt does it all for us
}

a1time Validity::getNotBefore() const
{
	a1time date;
	date.set(nbYear->text().toInt(), nbMon->currentItem() + 1, 
			nbDay->currentItem() +1, 0, 0, 0);
	return date;
}

a1time Validity::getNotAfter() const
{
	a1time date;
	date.set(naYear->text().toInt(), naMon->currentItem() + 1, 
			naDay->currentItem() +1, 0, 0, 0);
	return date;
}

void Validity::setNotBefore(const a1time &a)
{
	int y, m, d, g;
	a.ymdg(&y,&m,&d,&g);
	nbYear->setText(QString::number(y));
	nbMon->setCurrentItem(m-1);
	nbDay->setCurrentItem(d-1);
}

void Validity::setNotAfter(const a1time &a)
{
	int y, m, d, g;
	a.ymdg(&y,&m,&d,&g);
	naYear->setText(QString::number(y));
	naMon->setCurrentItem(m-1);
	naDay->setCurrentItem(d-1);
}

