/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2012 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <openssl/objects.h>
#include "OidResolver.h"
#include "lib/oid.h"
#include "lib/base.h"
#include "lib/func.h"
#include "lib/exception.h"

OidResolver::OidResolver(QWidget *parent)
	:QWidget(parent)
{
	setupUi(this);
	setWindowTitle(XCA_TITLE);
}

void OidResolver::searchOid(QString s)
{
	bool ok;
	int n;

	if (input->text() != s)	// Avoid moving the cursor at end if unchanged.
		input->setText(s);
	s = s.trimmed();
	n = s.toUInt(&ok);
	if (!ok)
		n = OBJ_txt2nid(CCHAR(s));
	if (n == NID_undef) {
		const char *clash = oid_name_clash[s];
		if (clash)
			n = OBJ_txt2nid(clash);
	}
	QString lo = s.toLower();
	if (n == NID_undef && s != lo)
		n = OBJ_txt2nid(CCHAR(lo));
	if (n == NID_undef && oid_lower_map.contains(lo))
		n = oid_lower_map[lo];
	ign_openssl_error();
	if (n == NID_undef) {
		ln->clear();
		sn->clear();
		oid->clear();
		nid->clear();
	} else {
		const ASN1_OBJECT *a = OBJ_nid2obj(n);
		ln->setText(OBJ_nid2ln(n));
		sn->setText(OBJ_nid2sn(n));
		nid->setText(QString("%1").arg(n));
		if (a) {
			try {
				oid->setText(OBJ_obj2QString(a, 1));
			} catch (errorEx &e) {
				oid->clear();
			}
		} else {
			oid->clear();
		}
	}
	ign_openssl_error();
	show();
	raise();
}
