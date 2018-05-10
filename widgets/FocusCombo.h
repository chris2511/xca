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
	QVariant currentItemData()
	{
		return QComboBox::itemData(currentIndex());
	}
	void addItemsData(const QStringList &textdata, const QString &selected)
	{
		int c = 0;
		Q_ASSERT(textdata.size() % 2  == 0);
		for (int i=0; i< textdata.size(); i+=2) {
			addItem(textdata[i], textdata[i+1]);
			if (textdata[i+1] == selected)
				c = i/2;
		}
		setCurrentIndex(c);
	}
};

#endif
