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
	return encAlgo(currentData().toInt());
}

void pkcs12EncBox::setCurrent(const encAlgo &md)
{
	int idx = findData(QVariant(md.getEncAlgoNid()));
	if (idx != -1) {
		setCurrentIndex(idx);
		wanted_encAlgo = NID_undef;
	} else {
		wanted_encAlgo = md.getEncAlgoNid();
	}
}

void pkcs12EncBox::setupEncAlgos(QList<int> nids)
{
	int md = currentData().toInt();

	if (wanted_encAlgo != NID_undef)
		md = wanted_encAlgo;
	clear();
	foreach(int nid, encAlgo::all_encAlgos) {
		if (nids.contains(nid))
			addItem(encAlgo(nid).displayName(), QVariant(nid));
	}
	setEnabled(count() > 0);
	setDefaultEncAlgo();
	if (md != NID_undef)
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
