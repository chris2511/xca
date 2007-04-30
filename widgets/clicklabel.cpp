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

	setAutoFillBackground(true);
	QPalette pal = palette();
	QColor col = QColor(0xff, 0xff, 0xff);
	pal.setColor(QPalette::Normal, QPalette::Window, col );
	pal.setColor(QPalette::Inactive, QPalette::Window, col );
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
	pal.setColor(QPalette::Normal, QPalette::WindowText, col );
	pal.setColor(QPalette::Inactive, QPalette::WindowText, col );
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


CopyLabel::CopyLabel(QWidget *parent)
	:QLabel(parent)
{
#if QT_VERSION >= 0x040200
	setTextInteractionFlags(
			Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);
#endif
}

