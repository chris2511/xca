/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2009 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef HASH_BOX_H
#define HASH_BOX_H

#include <qcombobox.h>
#include <openssl/evp.h>

class hashBox: public QComboBox
{
		Q_OBJECT
	private:
		static QString default_md;
		int backup;
		int key_type;
	public:
		hashBox(QWidget *parent);
		void setKeyType(int type);
		const EVP_MD *currentHash();
		QString currentHashName();
		void setCurrentAsDefault();
		void setDefaultHash();
		void setupHashes(QList<int> nids);
		void setupAllHashes();
		static void setDefault(QString def);
};

#endif
