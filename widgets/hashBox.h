/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2007 - 2011 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __HASH_BOX_H
#define __HASH_BOX_H

#include <QComboBox>
#include "lib/digest.h"

class hashBox: public QComboBox
{
	Q_OBJECT

  private:
	QString wanted_md{};
	int backup{};
	int key_type{};

  public:
	hashBox(QWidget *parent);
	const digest current() const;
	void setCurrent(const digest &md);
	void setupHashes(QList<int> nids);
	void setupAllHashes();
	void setDefaultHash();
};

#endif
