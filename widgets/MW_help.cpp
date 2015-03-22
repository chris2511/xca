/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "MainWindow.h"
#include <QtGui/QApplication>
#include <QtGui/QMimeSource>
#include <QtGui/QPixmap>
#include <QtGui/QLabel>
#ifndef OPENSSL_NO_EC
#include <openssl/ec.h>
#endif
#include "ui_About.h"
#include "ui_Help.h"
#include "lib/func.h"

void MainWindow::cmd_version() {
	fprintf(stderr, XCA_TITLE " Version " PACKAGE_VERSION "\n");
	exitApp = 1;
}

void MainWindow::cmd_help(const char* msg) {
	exitApp = 1;
	fprintf(stderr, XCA_TITLE " Version " PACKAGE_VERSION "\n"
		"\n"
		" -v show version information and exit\n"
		" -h shows this help screen and exit\n"
		" -e <type>:<name>  extract entry.\n"
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
	QString openssl, qt, cont, version, brainpool;
#ifndef OPENSSL_NO_EC
#ifdef NID_brainpoolP160r1
	EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_brainpoolP160r1);
	ign_openssl_error();
	if (group) {
		EC_GROUP_free(group);
		brainpool = "<p>ECC With RFC 5639 Brainpool curves"
#if OPENSSL_VERSION_NUMBER < 0x10002001L
	        "<br/>(Backported to " OPENSSL_VERSION_TEXT ")"
#endif
		;
	}
#endif
#else
	brainpool = "(Elliptic Curve Cryptography support disabled)";
#endif
	openssl = SSLeay_version(SSLEAY_VERSION);
	qt = qVersion();
	if (openssl != OPENSSL_VERSION_TEXT ||
	    qt != QT_VERSION_STR)
	{
		version = QString("<table border=0 width=500><tr>"
				"<td>Compile time:</td>"
				"<td>"OPENSSL_VERSION_TEXT"</td>"
				"<td>QT version: "QT_VERSION_STR"</td>"
				"</tr><tr>"
				"<td>Run time:</td>"
				"<td>%1</td>"
				"<td>QT version: %2</td>"
				"</tr></table>").arg(openssl).arg(qt);
	} else {
		version = QString("%1<br>QT version: %2").arg(openssl).arg(qt);
	}
	ui.setupUi(about);

	cont = QString(
	"<p><h3><center><u>XCA</u></center></h3>"
	"<p>Copyright 2001 - 2015 by Christian Hohnst&auml;dt\n"
	"<p>Version: <b>" PACKAGE_VERSION "</b>"
	"<p>%1<p>%2"
	"<p>http://sourceforge.net/projects/xca"
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
	"<tr><td><b>Frank Isemann</b></td><td><u>&lt;isemannf@firflabs.net&gt;</u></td></tr>"
	"<tr><td><b>Helmut Strobl</b></td><td><u>&lt;helmut.strobl@t-online.de&gt;</u></td></tr>"
	"</table><hr><center><u><b>Translations</b></u></center>"
	"<p><table>"
	"<tr><th>German</th><td>Christian Hohnst&auml;dt</td></tr>"
	"<tr><th>Russian</th><td>Pavel Belly &lt;pavel.belly@gmail.com&gt;</td></tr>"
	"<tr><th>French</th><td>Patrick Monnerat &lt;Patrick.Monnerat@datasphere.ch&gt;</td></tr>"
	"<tr><th>Croatian</th><td>Nevenko Bartolincic &lt;nevenko.bartolincic@gmail.com&gt;</td></tr>"
	"</table>").arg(brainpool).arg(version);

	about->setWindowTitle(XCA_TITLE);
	ui.image->setPixmap( *keyImg );
	ui.image1->setPixmap( *certImg );
	ui.textbox->setHtml(cont);
	about->exec();
	delete about;
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

