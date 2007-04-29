/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "clicklabel.h"

#include <qtooltip.h>
#include <qpalette.h>
#include <qcolor.h>

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
