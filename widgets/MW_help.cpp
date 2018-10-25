/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2017 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "MainWindow.h"
#include <QApplication>
#include <QMimeData>
#include <QPixmap>
#include <QLabel>
#ifndef OPENSSL_NO_EC
#include <openssl/ec.h>
#endif
#include "XcaDialog.h"
#include "ui_Help.h"
#include "lib/func.h"
#include "lib/entropy.h"

void MainWindow::cmd_version()
{
	fprintf(stderr, XCA_TITLE " Version %s\n", version_str(false));
	exitApp = 1;
}

void MainWindow::cmd_help(const char* msg)
{
	fprintf(stderr, XCA_TITLE " Version %s\n"
		"\n"
		" -v show version information and exit\n"
		" -h shows this help screen and exit\n"
		" -d expect the following argument to be the database name to use\n"
		" -i expect the following argument to be the index file to generate\n"
		" -I expect the following argument to be the base name the index file hierarchy to generate\n"
		" -x Exit after processing all commandline options\n\n", version_str(false));

	if (msg) {
		fprintf(stderr, "Cmdline Error: %s\n", msg);
	}
	exitApp = 1;
}

void MainWindow::about()
{
	QTextEdit *textbox = new QTextEdit(NULL);
	XcaDialog *about = new XcaDialog(this, x509, textbox,
					QString(), QString());
	about->aboutDialog(scardImg);
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
				"<td>" OPENSSL_VERSION_TEXT "</td>"
				"<td>QT version: " QT_VERSION_STR "</td>"
				"</tr><tr>"
				"<td>Run time:</td>"
				"<td>%1</td>"
				"<td>QT version: %2</td>"
				"</tr></table>").arg(openssl).arg(qt);
	} else {
		version = QString("%1<br>QT version: %2").arg(openssl).arg(qt);
	}
	Entropy::seed_rng();
	cont = QString(
	"<p><h3><center><u>XCA%8</u></center></h3>"
	"<p>Copyright 2001 - 2018 by Christian Hohnst&auml;dt\n"
	"<p>Version: %4<p>%1<p>%2" /* commithash, Brainpool, OpenSSL & Qt Version */
	"<p>http://hohnstaedt.de/xca"
	"<p>Entropy strength: %3"
	"<p><table border=\"0\">"
	"<tr><td>Installation path:</td><td>%5</td></tr>"
	"<tr><td>User settings path:</td><td>%6</td></tr>"
	"<tr><td>Working directory:</td><td>%7</td></tr>"
	"</table>"
	"<hr><table border=\"0\">"
	"<tr><th align=left>Christian Hohnst&auml;dt</th><td><u>&lt;christian@hohnstaedt.de&gt;</u></td></tr>"
	"<tr><td></td><td>Programming, Translation and Testing</td></tr>"
	"<tr><th align=left>Kerstin Steinhauff</th><td><u>&lt;tine@kerstine.de&gt;</td></u></tr>"
	"<tr><td></td><td>Arts and Graphics</td></tr>"
	"</table><hr><center><u><b>Maintained Translations</b></u></center>"
	"<p><table>"
	"<tr><td><b>German</b></td><td>Christian Hohnst&auml;dt &lt;christian@hohnstaedt.de&gt;</td></tr>"
	"<tr><td><b>French</b></td><td>Patrick Monnerat &lt;patrick@monnerat.net&gt;</td></tr>"
	"<tr><td><b>Croatian</b></td><td>Nevenko Bartolincic &lt;nevenko.bartolincic@gmail.com&gt;</td></tr>"
	"<tr><td><b>Slovak</b></td><td>Slavko &lt;linux@slavino.sk&gt;</td></tr>"
	"<tr><td><b>Polish</b></td><td>Jacek Tyborowski &lt;jacek@tyborowski.pl&gt;</td></tr>"
	"<tr><td><b>Portuguese (Brazil)</b></td><td>Vinicius Ocker &lt;viniciusockerfagundes@yandex.com&gt;</td></tr>"
	"<tr><td><b>Spanish</b></td><td>Miguel Romera &lt;mrmsoftdonation@gmail.com&gt;</td></tr>"
	"</table>").arg(brainpool).arg(version).arg(Entropy::strength())
			.arg(version_str(true)).arg(getPrefix())
			.arg(getUserSettingsDir())
			.arg(QString(Settings["workingdir"]))
			.arg(portable_app() ? " (Portable)" : "");

	textbox->setHtml(cont);
	textbox->setReadOnly(true);
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
#if defined(Q_OS_WIN32)
	path += "/";
#endif
	path += getDocDir() + "/";
#if defined(Q_OS_WIN32)
	path = path.replace("\\","/");
#endif
	uri = path + "xca.html";

	ui.textbox->setSource(QUrl(uri));
	ui.textbox->setSearchPaths(QStringList(path));
	h->setWindowTitle(XCA_TITLE);
	h->show();
}

