/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2007 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "hashBox.h"
#include "lib/base.h"
#include <QDebug>

hashBox::hashBox(QWidget *parent)
	:QComboBox(parent)
{
	setupAllHashes();
	setDefaultHash();
}

const digest hashBox::current() const
{
	return digest(currentText());
}

void hashBox::setCurrent(const digest &md)
{
	int idx = findText(md.name());
	if (idx != -1) {
		setCurrentIndex(idx);
		wanted_md = "";
	} else {
		wanted_md = md.name();
	}
}

void hashBox::setupHashes(QList<int> nids)
{
	QString md = currentText();

	if (!wanted_md.isEmpty())
		md = wanted_md;
	clear();
	foreach(int nid, digest::all_digests) {
		if (nids.contains(nid))
			addItem(digest(nid).name());
	}
	setEnabled(count() > 0);
	setDefaultHash();
	setCurrent(digest(md));
}

void hashBox::setupAllHashes()
{
	setupHashes(digest::all_digests);
}

void hashBox::setDefaultHash()
{
	setCurrent(digest::getDefault());
}
