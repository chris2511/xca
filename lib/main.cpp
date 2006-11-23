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
 *
 * http://www.hohnstaedt.de/xca
 * email: christian@hohnstaedt.de
 *
 * $Id$
 *
 */

#include <Qt/qapplication.h>
#include <Qt/qtranslator.h>
#include <Qt/qtextcodec.h>
#include <Qt/qdir.h>
#include <Qt/qtranslator.h>
#include "widgets/MainWindow.h"
#include "lib/func.h"
#ifdef WIN32
#include <windows.h>
#endif

int main( int argc, char *argv[] )
{
	int ret = 0, pkictr;
	QString locale;
	QTranslator qtTr( 0 );
	QTranslator xcaTr( 0 );
	MainWindow *mw;
	QApplication a( argc, argv );

#ifdef WIN32
	LANGID LangId = PRIMARYLANGID(GetUserDefaultLangID());
	switch (LangId) {
		case 0x07: locale="de"; break; //German
		case 0x0a: locale="es"; break; //Spanish
		case 0x0b: locale="fi"; break; //Finn
		case 0x0c: locale="fr"; break; //French
		case 0x0e: locale="hu"; break; //Hungarian
		case 0x19: locale="ru"; break; //Russian
		default: locale="c";
	}
#else
	locale = "C"; //QTextCodec::locale();
#warning Fix locale
#endif
	qtTr.load( QString( "qt_" ) + locale, "." );
	xcaTr.load( QString( "xca_" ) + locale, getPrefix() );

	a.installTranslator( &qtTr );
	a.installTranslator( &xcaTr );
	fprintf(stderr, "Locale: %s\nPrefix:%s\n",
		locale.data(), CCHAR(getPrefix()));

	mw = new MainWindow( NULL);
	if (mw->exitApp == 0) {
		mw->show();
		ret = a.exec();
	}
	delete mw;

	pkictr =  pki_base::get_pki_counter();
	if (pkictr)
		printf("PKI Counter (%d)\n", pkictr);

	return ret;
}
