/* vi: set sw=4 ts=4: */
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

#include "clicklabel.h"

#include <Qt/qtooltip.h>
#include <Qt/qpalette.h>
#include <Qt/qcolor.h>

ClickLabel::ClickLabel(QWidget *parent)
	:QLabel(parent)
{
	QFont fnt( font() );
	fnt.setBold(true);
	setFont( fnt );
	setFrameShape( QLabel::Panel );
	setFrameShadow( QLabel::Sunken );
	setAlignment( Qt::AlignCenter );
	setToolTip( tr("Double click for details") );

	QPalette pal = palette();
	QColor col = QColor(200, 200, 200);
	pal.setColor(QPalette::Normal, QPalette::Background, col );
	pal.setColor(QPalette::Inactive, QPalette::Background, col );
	setPalette( pal );
}

void ClickLabel::mouseDoubleClickEvent ( QMouseEvent * e )
{
	QWidget::mouseDoubleClickEvent(e);
	emit doubleClicked(text());
}

void ClickLabel::setColor(const QColor &col)
{
	QPalette pal = palette();
	pal.setColor(QPalette::Normal, QPalette::Foreground, col );
	pal.setColor(QPalette::Inactive, QPalette::Foreground, col );
	setPalette( pal );
}

void ClickLabel::setRed()
{
	setColor( QColor( 192, 32, 32) );
}

void ClickLabel::setGreen()
{
	setColor( QColor( 32, 192, 32) );
}

void ClickLabel::disableToolTip()
{
	setToolTip(QString());
}
