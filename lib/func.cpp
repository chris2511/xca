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
#include "lib/asn1time.h"
#include "widgets/validity.h"
#include <qdir.h>
#include <qlabel.h>
#include <qlineedit.h>
#include <qcombobox.h>
#include <qmessagebox.h>
#include <qapplication.h>

#ifdef WIN32
#include <windows.h>
#include <shlobj.h>
#endif

QPixmap *loadImg(const char *name )
{
	QString path = getPrefix();
	path += QDir::separator();
	return new QPixmap(path + name);
}

/* returns e.g. /usr/local/share/xca for unix systems
 * or HKEY_LOCAL_MACHINE->Software->xca for WIN32 
 * (e.g. c:\Program Files\xca )
 */

QString getPrefix() 
{

#ifdef WIN32
static unsigned char inst_dir[100]="";
if (inst_dir[0] == '\0') { 
	/* if we already once discovered the directory
	 * we need not doing it again 
	 */
	LONG lRc;
	HKEY hKey;
	lRc=RegOpenKeyEx(HKEY_LOCAL_MACHINE, "Software\\xca",0,KEY_READ, &hKey);
	if(lRc!= ERROR_SUCCESS){
		/* No key error */
		QMessageBox::warning(NULL,XCA_TITLE,
			"Registry Key: 'HKEY_LOCAL_MACHINE->Software->xca' not found");
                inst_dir[0] = '\0';
	}
	else{
        	ULONG dwLength = 100;
                lRc=RegQueryValueEx(hKey,"Install_Dir",NULL,NULL, inst_dir, &dwLength);
		if(lRc!= ERROR_SUCCESS){
			/* No key error */
	                QMessageBox::warning(NULL, XCA_TITLE,
			"Registry Key: 'HKEY_LOCAL_MACHINE->Software->xca->Install_Dir' not found");
                	inst_dir[0] = '\0';
		}
	}
        lRc=RegCloseKey(hKey);
}

QString ret = (char *)inst_dir;
return ret;

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

/* This function returns the baseDirectory for storing private data.
 * on Unix: 		$HOME/xca 
 * on WIN 98/ME:	c:\Program Files\xca
 * on NT, W2K,XP	c:\Documents and Settings\%USER%\Application Data\xca
 */

QString getBaseDir()
{
	QString baseDir = "";
#ifdef WIN32
	unsigned char reg_path_buf[255] = "";
	TCHAR data_path_buf[255];

	// verification registry keys
	LONG lRc;
    HKEY hKey;
	DWORD dwDisposition;
	DWORD dwLength = 255;
    lRc=RegOpenKeyEx(HKEY_LOCAL_MACHINE, "Software\\xca",0,KEY_READ, &hKey);
    if(lRc!= ERROR_SUCCESS){
		QMessageBox::warning(NULL, XCA_TITLE,
			"Registry Key: 'HKEY_LOCAL_MACHINE->Software->xca' not found. ReInstall Xca.");
		qFatal("Installation problem");
	}
    else {
		lRc=RegQueryValueEx(hKey,"Install_Dir",NULL,NULL, reg_path_buf, &dwLength);
        if(lRc!= ERROR_SUCCESS){
			QMessageBox::warning(NULL, XCA_TITLE,
				"Registry Key: 'HKEY_LOCAL_MACHINE->Software->xca->Install_Dir' not found. ReInstall Xca.");		
			qFatal("Installation problem");
		}
		lRc=RegCloseKey(hKey);
	}
	lRc=RegOpenKeyEx(HKEY_CURRENT_USER,"Software\\xca",0,KEY_ALL_ACCESS, &hKey);
    if(lRc!= ERROR_SUCCESS)
    {
		//First run for current user
		lRc=RegCloseKey(hKey);
		lRc=RegCreateKeyEx(HKEY_CURRENT_USER,"Software\\xca",0,NULL,REG_OPTION_NON_VOLATILE,KEY_ALL_ACCESS,
		NULL,&hKey, &dwDisposition);
		
		//setup data dir for current user
		OSVERSIONINFOEX osvi;
		BOOL bOsVersionInfoEx;
		LPITEMIDLIST pidl=NULL; 

		ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
		osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

		if(!(bOsVersionInfoEx=GetVersionEx((OSVERSIONINFO*)&osvi))){
			osvi.dwOSVersionInfoSize = sizeof (OSVERSIONINFO);
			if (! GetVersionEx ( (OSVERSIONINFO *) &osvi) ) return FALSE;
		}
		if (osvi.dwPlatformId == VER_PLATFORM_WIN32_NT){
			if(SUCCEEDED(SHGetSpecialFolderLocation(NULL,CSIDL_APPDATA,&pidl))){
				SHGetPathFromIDList(pidl,data_path_buf);
				lstrcat(data_path_buf, "\\xca");	 
			}
		}else{
			strncpy(data_path_buf,(char *)reg_path_buf,255);
			strcat(data_path_buf,"\\data");
		}
		baseDir = QString::fromLocal8Bit(data_path_buf);
		// save in registry
		lRc=RegSetValueEx(hKey,"data_path",0,REG_SZ,(BYTE*)data_path_buf, 255);
		lRc=RegCloseKey(hKey);
		QMessageBox::warning(NULL,XCA_TITLE, QString::fromLatin1("New data dir create:")+ baseDir);
		QMessageBox::warning(NULL,XCA_TITLE, QString::fromLatin1("WARNING: If you have updated your 'xca' application \n you have to copy your 'xca.db' from 'C:\\PROGAM FILES\\XCA\\' to ") + baseDir + QString::fromLatin1(" \n or change HKEY_CURRENT_USER->Software->xca->data_path key"));
        }
	else{
		dwLength = sizeof(data_path_buf);
		lRc=RegQueryValueEx(hKey,"data_path",NULL,NULL, (BYTE*)data_path_buf, &dwLength);
		if ((lRc != ERROR_SUCCESS)) {
			QMessageBox::warning(NULL,XCA_TITLE, "Registry Key: 'HKEY_CURRENT_USER->Software->xca->data_path' not found.");
			//recreate data dir for current user
			OSVERSIONINFOEX osvi;
			BOOL bOsVersionInfoEx;
			LPITEMIDLIST pidl=NULL; 

			ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
			osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

			if(!(bOsVersionInfoEx=GetVersionEx((OSVERSIONINFO*)&osvi))){
				osvi.dwOSVersionInfoSize = sizeof (OSVERSIONINFO);
				if (! GetVersionEx ( (OSVERSIONINFO *) &osvi) ) return FALSE;
			}
			if (osvi.dwPlatformId == VER_PLATFORM_WIN32_NT){
				if(SUCCEEDED(SHGetSpecialFolderLocation(NULL,CSIDL_APPDATA,&pidl))){
					SHGetPathFromIDList(pidl,data_path_buf);
					lstrcat(data_path_buf, "\\xca");	  
				}
			}else{
				strncpy(data_path_buf,(char *)reg_path_buf,255);
				strcat(data_path_buf,"\\data");
			}
			baseDir = QString::fromLocal8Bit(data_path_buf);
			// save in registry
			lRc=RegSetValueEx(hKey,"data_path",0,REG_SZ,(BYTE*)data_path_buf, 255);
			lRc=RegCloseKey(hKey);
			QMessageBox::warning(NULL,XCA_TITLE, QString::fromLatin1("data dir:")+ baseDir);
		}

		lRc=RegCloseKey(hKey);
		baseDir = QString::fromLocal8Bit(data_path_buf);
	}
// 

#elif __APPLE_CC__
	baseDir = getPrefix() + "/xca";
#else
#ifdef BASEDIR
	baseDir = BASEDIR;
#else
	baseDir = QDir::homeDirPath();
	baseDir += QDir::separator();
	baseDir += "xca";
#endif
#endif
	return baseDir;
}

void applyTD(int number, int range, bool mnc, Validity *nb, Validity *na)
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
        QMessageBox::warning(NULL, XCA_TITLE,
            "Time difference too big\nYou must set it manually." );
        return;
    }
    nb->setDate(a.now(), midnight);
    na->setDate(a.now(delta * d_fac), midnight* (-1));
}
