/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2011 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __OID_H
#define __OID_H

class QString;
#include <QList>

extern int first_additional_oid;

typedef QList<int> NIDlist;
/* reads additional OIDs from a file: oid, sn, ln */

void initOIDs();

/* reads a list of OIDs/SNs from a file and turns them into a QValueList
 * of integers, representing the NIDs. Usually to be used by NewX509 for
 * the list of ExtendedKeyUsage and Distinguished Name
 */

NIDlist readNIDlist(QString fname);
#endif
