/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __FOCUSCOMBO_H
#define __FOCUSCOMBO_H

#include <QComboBox>

class focusCombo : public QComboBox
{
    public:
	focusCombo(QWidget *parent) : QComboBox(parent) { }
	void hidePopup()
	{
		QComboBox::hidePopup();
		emit highlighted(currentIndex());
	}
};

#endif
