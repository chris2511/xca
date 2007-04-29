/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef CLICKLABEL_H
#define CLICKLABEL_H

#include <qlabel.h>

class QMouseEvent;

class ClickLabel : public QLabel
{
  Q_OBJECT

  public:
	ClickLabel(QWidget *parent);
	void setRed();
	void setGreen();
	void disableToolTip();

  protected:
	void mouseDoubleClickEvent ( QMouseEvent * e );
	void setColor(const QColor &col);

  signals:
	void doubleClicked(QString text);
};

#endif
