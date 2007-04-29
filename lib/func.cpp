/* vi: set sw=4 ts=4: */
/*
 * Copyright (C) 2001 Christian Hohnstaedt.
 *
 *  All rights reserved.
 *
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *  - Neither the name of the author nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * This program links to software with different licenses from:
 *
 *	http://www.openssl.org which includes cryptographic software
 *	written by Eric Young (eay@cryptsoft.com)"
 *
 *	http://www.trolltech.com
 *
 *
 * http://www.hohnstaedt.de/xca
 * email: christian@hohnstaedt.de
 *
 * $Id$
 *
 */


#include "func.h"
#include "lib/asn1time.h"
#include "widgets/validity.h"
#include <Qt/qdir.h>
#include <Qt/qlabel.h>
#include <Qt/qlineedit.h>
#include <Qt/qcombobox.h>
#include <Qt/qmessagebox.h>
#include <Qt/qapplication.h>
/* for htons() */
#include <netinet/in.h>

#ifdef WIN32
#include <windows.h>
#include <shlobj.h>
#endif

QPixmap *loadImg(const char *name )
{
	return new QPixmap(QString(":") + name);
}

/* returns e.g. /usr/local/share/xca for unix systems
 * or HKEY_LOCAL_MACHINE->Software->xca for WIN32
 * (e.g. c:\Program Files\xca )
 */

QString getPrefix()
{
#ifdef WIN32
	static char inst_dir[100] = "";
	char *p;
	ULONG dwLength = 100;
	LONG lRc;
	HKEY hKey;

	if (inst_dir[0] != '\0') {
		/* if we already once discovered the directory just return it */
		return QString(inst_dir);
	}
	// fallback: directory of xca.exe 
	GetModuleFileName(0, inst_dir, dwLength - 1);
	p = strrchr(inst_dir, '\\');
	if (p) {
		*p = '\0';
		return QString(inst_dir);
	}
	p = inst_dir;
	*p = '\0';
	QMessageBox::information(NULL, XCA_TITLE, QString(inst_dir), "OK");
	lRc = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "Software\\xca", 0, KEY_READ, &hKey);
	if (lRc != ERROR_SUCCESS) {
		QMessageBox::warning(NULL,XCA_TITLE,
				"Registry Key: 'HKEY_LOCAL_MACHINE->Software->xca' not found");
		return QString(inst_dir);
	}
	lRc = RegQueryValueEx(hKey, "Install_Dir", NULL, NULL,
			(unsigned char *)inst_dir, &dwLength);
	if (lRc != ERROR_SUCCESS){
		QMessageBox::warning(NULL, XCA_TITLE, "Registry Key: "
				"'HKEY_LOCAL_MACHINE->Software->xca->Install_Dir' not found");
	}
	lRc = RegCloseKey(hKey);
	return QString(inst_dir);

#elif __APPLE_CC__
	QDir d;
	d = qApp->applicationDirPath();
	d.cdUp();
	return d.canonicalPath() + "/Resources";
#else

	QString ret = PREFIX;
	ret += "/share/xca";
	return ret;
#endif

}

QString getHomeDir()
{
	QString hd;
#ifdef WIN32
	LPITEMIDLIST pidl = NULL;
	TCHAR buf[255] = "";
	if (SUCCEEDED(SHGetSpecialFolderLocation(NULL, CSIDL_PERSONAL, &pidl))) {
		SHGetPathFromIDList(pidl, buf);
	}
	hd = buf;
#elif __APPLE_CC__
	hd = getPrefix() + "/xca";
#else
#ifdef BASEDIR
	hd = BASEDIR;
#else
	hd = QDir::homePath();
#endif
#endif
	return hd;
}

void applyTD(QWidget *parent, int number, int range, bool mnc,
		Validity *nb, Validity *na)
{
#define d_fac (60 * 60 * 24)
    int faktor[] = { 1, 30, 365 }, midnight, delta;
    a1time a;
    time_t t;

    midnight = mnc? 1:0;

    if (range>2 || range<0) range = 0;
    time(&t);
    delta = faktor[range] * number;

	// one day less if we go from 0:00:00 to 23:59:59
	if (mnc) delta -=1;

    t /= d_fac;
    if (delta + t > 24850){
        QMessageBox::warning(parent, XCA_TITLE,
            "Time difference too big\nYou must set it manually." );
        return;
    }
    nb->setDate(a.now(), midnight);
    na->setDate(a.now(delta * d_fac), midnight* (-1));
}

QString asn1ToQString(const ASN1_STRING *str)
{
	QString qs;
	unsigned short *bmp;
	int i;

	if (!str)
		return qs;

	switch (str->type) {
		case V_ASN1_BMPSTRING:
			bmp = (unsigned short*)str->data;
			for (i = 0; i < str->length/2; i++)
				qs += QChar(ntohs(bmp[i]));
			break;
		case V_ASN1_UTF8STRING:
			qs = QString::fromUtf8((const char*)str->data, str->length);
			break;
		case V_ASN1_T61STRING:
			qs = QString::fromLocal8Bit((const char*)str->data, str->length);
			break;
		default:
			qs = QString::fromLatin1((const char*)str->data, str->length);
	}
	//printf("Convert %s string to '%s'\n", ASN1_tag2str(str->type),CCHAR(qs));
	return qs;
}
