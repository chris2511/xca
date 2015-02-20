/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2007 - 2011 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __HASH_BOX_H
#define __HASH_BOX_H

#include <QComboBox>
#include <openssl/evp.h>

class hashBox: public QComboBox
{
		Q_OBJECT
	private:
		static QString default_md;
		QString wanted_md;
		int backup;
		int key_type;
	public:
		hashBox(QWidget *parent);
		void setKeyType(int type);
		const EVP_MD *currentHash();
		QString currentHashName();
		void setCurrentMD(const EVP_MD *md);
		void setCurrentAsDefault();
		void setDefaultHash();
		void setupHashes(QList<int> nids);
		void setupAllHashes();
		void setCurrentString(QString md);
		static void setDefault(QString def);
		static void resetDefault();
};

#endif
