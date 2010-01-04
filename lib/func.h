/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef FUNC_H
#define FUNC_H

#include <openssl/asn1.h>
#include <qpixmap.h>
#include "base.h"

class Validity;

QPixmap *loadImg(const char *name);
QString getPrefix();
QString getHomeDir();
QString getDocDir();
QString getUserSettingsDir();
QString getFullFilename(const QString &filename, const QString &selectedFilter);

QByteArray filename2bytearray(const QString &fname);
QString filename2QString(const char *fname);

void applyTD(QWidget *parent, int number, int range, bool mnc,
		Validity *nb, Validity *na);
QString asn1ToQString(const ASN1_STRING *str);
ASN1_STRING *QStringToAsn1(QString s, int nid);

const char *OBJ_ln2sn(const char *ln);
const char *OBJ_sn2ln(const char *sn);

QString changeFilenameSuffix(QString fn, const QStringList &suffixlist,
				int selected);
bool mayWriteFile(const QString &fname);

#define QString2filename(str) filename2bytearray(str).constData()
#endif
