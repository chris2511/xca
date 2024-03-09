/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2007 - 2011 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __PKCS12_ENC_BOX_H
#define __PKCS12_ENC_BOX_H

#include <QComboBox>
#include "lib/pki_pkcs12.h"

class pkcs12EncBox: public QComboBox
{
	Q_OBJECT

	private:
		int wanted_encAlgo{};

	public:
		pkcs12EncBox(QWidget *parent);
		const encAlgo current() const;
		void setCurrent(const encAlgo &md);
		void setupEncAlgos(QList<int> nids);
		void setupAllEncAlgos();
		void setDefaultEncAlgo();
};

#endif
