/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2007 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "pkcs12EncBox.h"
#include <QDebug>

pkcs12EncBox::pkcs12EncBox(QWidget *parent)
	:QComboBox(parent)
{
	setupAllEncAlgos();
}

const encAlgo pkcs12EncBox::current() const
{
	return encAlgo(currentText());
}

void pkcs12EncBox::setCurrent(const encAlgo &md)
{
	int idx = findText(md.name());
	if (idx != -1) {
		setCurrentIndex(idx);
		wanted_encAlgo = "";
	} else {
		wanted_encAlgo = md.name();
	}
}

void pkcs12EncBox::setupEncAlgos(QList<int> nids)
{
	QString md = currentText();

	if (!wanted_encAlgo.isEmpty())
		md = wanted_encAlgo;
	clear();
	foreach(int nid, encAlgo::all_encAlgos) {
		if (nids.contains(nid))
			addItem(encAlgo(nid).name());
	}
	setEnabled(count() > 0);
	setDefaultEncAlgo();
	if (!md.isEmpty())
		setCurrent(encAlgo(md));
	else
		setDefaultEncAlgo();
}

void pkcs12EncBox::setupAllEncAlgos()
{
	setupEncAlgos(encAlgo::all_encAlgos);
}

void pkcs12EncBox::setDefaultEncAlgo()
{
	setCurrent(encAlgo::getDefault());
}
