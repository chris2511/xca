/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __ITEMCOMBO_H
#define __ITEMCOMBO_H

#include <QList>
#include <QComboBox>

#include "lib/pki_base.h"

class itemCombo : public QComboBox
{
    public:
	itemCombo(QWidget *parent) : QComboBox(parent) { }
	void insertPkiItems(QList<pki_base*> items) {
		foreach(pki_base *p, items) {
			addItem(p->comboText(), QVariant::fromValue(p));
		}
	}
	pki_base *currentPkiItem() {
		return itemData(currentIndex()).value<pki_base*>();
	}
	int setCurrentPkiItem(pki_base *p) {
		int idx = findData(QVariant::fromValue(p));
		setCurrentIndex(idx);
		return idx;
	}
};

#endif
