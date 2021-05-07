/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2020 Christian Hohnstaedt.
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

const QList<QStringList> MainWindow::getTranslators() const
{
	return QList<QStringList> {
	QStringList{ "", tr("System") },
	QStringList{ "zh_CN", tr("Chinese"),
		"Xczh", "xczh.me", "foxmail.com" },
	QStringList{ "hr", tr("Croatian"),
		"Nevenko Bartolincic", "nevenko.bartolincic", "gmail.com" },
	QStringList{ "nl", tr("Dutch"), "Guido Pennings" },
	QStringList{ "en", tr("English") },
	QStringList{ "fr", tr("French"),
		"Patrick Monnerat", "patrick", "monnerat.net" },
	QStringList{ "de", tr("German"),
		"Christian Hohnstädt", "christian", "hohnstaedt.de" },
	QStringList{ "it", tr("Italian"),
		"Paolo Basenghi", "paul69", "libero.it" },
	QStringList{ "ja", tr("Japanese"),
		"ぶらすず", "burasuzu", "gmail.com" },
	QStringList{ "pl", tr("Polish"),
		"Jacek Tyborowski", "jacek", "tyborowski.pl" },
	QStringList{ "pt_BR", tr("Portuguese in Brazil"),
		"Ulisses Guedes", "uli1958", "hotmail.com" },
	QStringList{ "ru", tr("Russian") },
	QStringList{ "sk", tr("Slovak"),
		"Slavko", "linux", "slavino.sk" },
	QStringList{ "es", tr("Spanish"),
		"Miguel Romera", "mrmsoftdonation", "gmail.com" },
	QStringList{ "tr", tr("Turkish") },
	};
};

void MainWindow::about()
{
	QTextEdit *textbox = new QTextEdit(NULL);
	XcaDialog *about = new XcaDialog(this, x509, textbox,
					QString(), QString());
	about->aboutDialog(QPixmap(":scardImg"));
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
	QStringList rows;
	foreach(QStringList sl, getTranslators()) {
		QString email;
		QStringList tag { "<td>", "</td>" };
		if (sl.size() < 3)
			continue;
		if (sl.size() > 4)
			email = QString("<%1@%2>").arg(sl[3]).arg(sl[4]);
		QString lang(QLocale::languageToString(QLocale(sl[0]).language()));
		QStringList row {
			QString("<b>%1</b>").arg(lang),
			htmlEscape(sl[2]),
			htmlEscape(email),
		};
		rows << tag[0] + row.join(tag[0] + tag[1]) + tag[1];
	}

	Entropy::seed_rng();
	cont = QString(
	"<p><h3><center><u>XCA%8</u></center></h3>"
	"<p>Copyright 2001 - 2021 by Christian Hohnstädt\n"
	"<p>Version: %4<p>%1<p>%2" /* commithash, Brainpool, OpenSSL & Qt Version */
	"<p><a href=\"https://hohnstaedt.de/xca\">https://hohnstaedt.de/xca</a>"
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
	"<p><table><tr>%9</tr></table>").arg(brainpool)
			.arg(version)
			.arg(Entropy::strength())
			.arg(version_str(true))
			.arg(nativeSeparator(getPrefix()))
			.arg(nativeSeparator(getUserSettingsDir()))
			.arg(nativeSeparator(QString(Settings["workingdir"])))
			.arg(portable_app() ? " (Portable)" : "")
			.arg(rows.join("</tr><tr>"));

	textbox->setHtml(cont);
	textbox->setReadOnly(true);
	about->exec();
	delete about;
}
