/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2009 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "pki_key.h"
#include "func.h"
#include "db.h"
#include <qapplication.h>
#include <widgets/MainWindow.h>

pki_key::pki_key(const QString name)
        :pki_base(name)
{
	ucount = 0;
	class_name = "pki_key";
}

pki_key::pki_key(const pki_key *pk)
	:pki_base(pk->desc)
{
	ucount = pk->ucount;
}

QString pki_key::getIntNameWithType()
{
	return getIntName() + " (" + getTypeString() + ")";
}

QString pki_key::removeTypeFromIntName(QString n)
{
	int i;
	if (n.right(1) != ")" )
		return n;
	i = n.lastIndexOf(" (");
	if (i > 0)
		n.truncate(i);
	return n;
}

bool pki_key::isScard()
{
	return false;
}

bool pki_key::isPrivKey() const
{
	return !isPubKey();
}

int pki_key::incUcount()
{
	ucount++;
	return ucount;
}
int pki_key::decUcount()
{
	ucount--;
	return ucount;
}

int pki_key::getUcount()
{
	return ucount;
}

QVariant pki_key::column_data(int col)
{
	QStringList sl;
	sl << tr("Common") << tr("Private") << tr("Bogus") << tr("PIN");
	switch (col) {
		case 0:
			return QVariant(getIntName());
		case 1:
			return QVariant(getTypeString());
		case 2:
			return QVariant(length());
		case 3:
			return QVariant(getUcount());
		case 4:
			if (isPubKey())
				return QVariant(tr("No password"));
			if (ownPass<0 || ownPass>3)
				return QVariant("Holla die Waldfee");
			return QVariant(sl[ownPass]);
	}
	return QVariant();
}

