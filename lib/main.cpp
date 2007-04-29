/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <qapplication.h>
#include <qtranslator.h>
#include <qtextcodec.h>
#include <qdir.h>
#include <qtranslator.h>
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
	fprintf(stderr, "Locale:'%s'; Prefix:'%s'\n",
		CCHAR(locale), CCHAR(getPrefix()));

	mw = new MainWindow( NULL);
	mw->show();
	mw->read_cmdline();
	if (mw->exitApp == 0) {
		ret = a.exec();
	}

	delete mw;

	pkictr =  pki_base::get_pki_counter();
	if (pkictr)
		printf("PKI Counter (%d)\n", pkictr);

	return ret;
}
