/* vi: set sw=4 ts=4: */
#/*
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
 * 	written by Eric Young (eay@cryptsoft.com)"
 *
 *	http://www.sleepycat.com
 *
 *	http://www.trolltech.com
 * 
 *
 *
 * http://www.hohnstaedt.de/xca
 * email: christian@hohnstaedt.de
 *
 * $Id$
 *
 */                           


#include "func.h"
#include <qdir.h>
#include <qmessagebox.h>

#ifdef WIN32
#include <windows.h>
#endif

QPixmap *loadImg(const char *name )
{
	QString path = getPrefix();
	path += QDir::separator();
	return new QPixmap(path + name);
}

QString getPrefix() 
{
	/* returns e.g. /usr/local/share/xca for unix systems
	 * or HKEY_LOCAL_MACHINE->Software->xca for WIN32 */

#ifdef WIN32
static unsigned char inst_dir[100]="";
if (inst_dir[0] == '\0') { 
	/* if we already once discovered the directory
	 * we need not doing it again 
	 */
	LONG lRc;
	HKEY hKey;
	lRc=RegOpenKeyEx(HKEY_LOCAL_MACHINE, "Software\xca",0,KEY_READ, &hKey);
	if(lRc!= ERROR_SUCCESS){
		// No key error
		QMessageBox::warning(NULL,XCA_TITLE,
			"Registry Key: 'HKEY_LOCAL_MACHINE->Software->xca' not found");
                inst_dir[0] = '\0';
	}
	else {
        	ULONG dwLength = 100;
                lRc=RegQueryValueEx(hKey,"Install_Dir",NULL,NULL, inst_dir, &dwLength);
		if(lRc!= ERROR_SUCCESS){
			// No key error
	                QMessageBox::warning(NULL, XCA_TITLE,
			"Registry Key: 'HKEY_LOCAL_MACHINE->Software->xca->Install_Dir' not found");
                	inst_dir[0] = '\0';
		}
	}
        lRc=RegCloseKey(hKey);
}

QString ret = inst_dir;
return ret;

#else

	QString ret = PREFIX;
	//ret += "/share/xca";
	return ret;
#endif


}

