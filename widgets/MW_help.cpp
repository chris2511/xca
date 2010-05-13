/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2009 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "MainWindow.h"
#include <qapplication.h>
#include <qmime.h>
#include <qpixmap.h>
#include <qlabel.h>
#include "ui_About.h"
#include "ui_Help.h"
#include "lib/func.h"

void MainWindow::cmd_version() {
	fprintf(stderr, XCA_TITLE " Version " VER "\n");
	exitApp = 1;
}

void MainWindow::cmd_help(const char* msg) {
	exitApp = 1;
	fprintf(stderr, XCA_TITLE " Version " VER "\n"
		"\n"
		" -v show version information and exit\n"
		" -h shows this help screen and exit\n"
		" -k expect all following non-option arguments to be RSA keys\n"
		" -r expect all following non-option arguments to be\n"
		"    Certificate signing requests or SPKAC requests\n"
		" -c expect all following non-option arguments to be Certificates\n"
		" -p expect all following non-option arguments to be PKCS#12 files\n"
		" -7 expect all following non-option arguments to be PKCS#7 files\n"
		" -l expect all following non-option arguments to be Revocation lists\n"
		" -t expect all following non-option arguments to be XCA templates\n"
		" -P expect all following non-option arguments to be PEM encoded 'thingies'\n"
		" -d expect the following argument to be the database name to use\n"
		" -x Exit after processing all commandline options\n\n");

	if(msg) {
		fprintf(stderr, "Cmdline Error: %s\n", msg);
	}
}

void MainWindow::about()
{
	Ui::About ui;
	QDialog *about = new QDialog(this, 0);

	ui.setupUi(about);

	QString cont;
	cont.sprintf("<p><h3><center><u>XCA</u></center></h3>"
	"<p>Copyright 2001 - 2010 by Christian Hohnst&auml;dt\n"
	"<p>Version : <b>" VER "</b>"
	"<p>%s<br>QT: %s"
	"<hr><table border=0>"
	"<tr><th align=left>Christian Hohnst&auml;dt</th><td><u>&lt;christian@hohnstaedt.de&gt;</u></td></tr>"
	"<tr><td></td><td>Programming, Translation and Testing</td></tr>"
	"<tr><th align=left>Kerstin Steinhauff</th><td><u>&lt;tine@kerstine.de&gt;</td></u></tr>"
	"<tr><td></td><td>Arts and Graphics</td></tr>"
	"<tr><th align=left>Ilya Kozhevnikov</th><td><u>&lt;ilya@ef.unn.ru&gt;</u></td></tr>"
	"<tr><td></td><td>Windows registry stuff</td></tr>"
	"<tr><th align=left>Wolfgang Glas</th><td><u>&lt;wolfgang.glas@ev-i.at&gt;</u></td></tr>"
	"<tr><td></td><td>SPKAC support and Testing</td></tr>"
	"<tr><th align=left>Geoff Beier</th><td><u>&lt;geoffbeier@gmail.com&gt;</u></td></tr>"
	"<tr><td></td><td>MAC OSX support and Testing</td></tr>"
	"</table><hr><center><u><b>General support</b></u></center>"
	"<p><table>"
	"<tr><td><b>Mark Foster</b></td><td><u>&lt;mark@foster.cc&gt;</u></td></tr>"
	"<tr><td><b>Thorsten Weiss</b></td><td><u>&lt;weiss2@gmx.de&gt;</u></td></tr>"
	"<tr><td><b>Oobj</b></td><td><u>&lt;www.oobj.com.br&gt;</u></td></tr>"
	"</table><hr><center><u><b>Translations</b></u></center>"
	"<p><table>"
	"<tr><th>German</th><td>Christian Hohnst&auml;dt</td></tr>"
	"<tr><th>Russian</th><td>Pavel Belly &lt;pavel.belly@gmail.com&gt;</td></tr>"
	"</table>",
	OPENSSL_VERSION_TEXT, QT_VERSION_STR );

	about->setWindowTitle(tr(XCA_TITLE));
	ui.image->setPixmap( *keyImg );
	ui.image1->setPixmap( *certImg );
	ui.textbox->setHtml(cont);
	about->exec();
	delete about;
}

void MainWindow::donations()
{
	Ui::About ui;
	QDialog *d = new QDialog(this, 0);

	ui.setupUi(d);

	QString cont;
	cont.sprintf("<p><h3><center><u>XCA</u></center></h3>"
	"<p>This program is free software."
	"<p>It doesn't bother you with Pop-Ups, Countdown-Timers, "
	"commercials or any type of 'Register Now' buttons. "
	"Nor are there any constraints or any limited functionality."
	"<p>Everybody who wants to support my work at XCA may use "
	"my PayPal account: <b>&lt;christian@hohnstaedt.de&gt;</b> "
	"for a donation."
	"<p>Every donator will in return be honored in the about dialog "
	"of the next version."
	);

	d->setWindowTitle(tr(XCA_TITLE));
	ui.image->setPixmap( *keyImg );
	ui.image1->setPixmap( *certImg );
	ui.textbox->setHtml(cont);
	d->exec();
}

void MainWindow::help()
{
	QDialog *h = new QDialog(this, 0);
	QString path, uri;
	Ui::Help ui;
	ui.setupUi(h);

	path = QString("file://");
#ifdef WIN32
	path += "/";
#endif
	path += getDocDir() + "/";
#ifdef WIN32
	path = path.replace("\\","/");
#endif
	uri = path + "xca.html";

	ui.textbox->setSource(QUrl(uri));
	ui.textbox->setSearchPaths(QStringList(path));
	h->setWindowTitle(tr(XCA_TITLE));
	h->show();
}

