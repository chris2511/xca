/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QtGui/QApplication>
#include <QtCore/QTranslator>
#include <QtCore/QTextCodec>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include "widgets/MainWindow.h"
#include "lib/func.h"
#include "lib/db.h"
#include "lib/main.h"
#ifdef WIN32
#include <windows.h>
#endif

QLocale XCA_application::lang = QLocale::system();

void XCA_application::setMainwin(MainWindow *m)
{
	mainw = m;
	connect(this, SIGNAL(openFiles(QStringList &)),
		m, SLOT(openURLs(QStringList &)));
}

XCA_application::XCA_application(int &argc, char *argv[])
	:QApplication(argc, argv)
{
	qtTr = NULL;
	xcaTr = NULL;
	mainw = NULL;

	QFile file(getUserSettingsDir() +
			QDir::separator() + "defaultlang");

	if (file.open(QIODevice::ReadOnly)) {
		lang = QLocale(QString(file.read(128)));
	}
	setupLanguage(lang);
#ifdef Q_WS_MAC
	QStringList libp = libraryPaths();
	libp.prepend(applicationDirPath() + "/../Plugins");
	setLibraryPaths(libp);
#endif
}

void XCA_application::setupLanguage(QLocale l)
{
	QStringList dirs;

	lang = l;
	if (qtTr) {
		removeTranslator(qtTr);
		delete qtTr;
	}
	qtTr = new XcaTranslator();
	if (xcaTr) {
		removeTranslator(xcaTr);
		delete xcaTr;
	}
	xcaTr = new XcaTranslator();
	dirs
#ifdef XCA_DEFAULT_QT_TRANSLATE
		<< XCA_DEFAULT_QT_TRANSLATE
#endif
		<< getPrefix()
#ifndef WIN32
		<< "/usr/local/share/qt4/translations/"
		<< "/usr/share/qt4/translations/"
		<< "/usr/share/qt/translations/"
#endif
		;

	foreach(QString dir, dirs) {
		if (qtTr->load(lang, "qt", dir)) {
			break;
		}
	}
	xcaTr->load(lang, "xca", getPrefix());

	installTranslator(qtTr);
	installTranslator(xcaTr);
}

void XCA_application::switchLanguage(QAction* a)
{
	QLocale lang = a->data().toLocale();
	setupLanguage(lang);

	QString dir = getUserSettingsDir();
	QFile file(dir +QDir::separator() +"defaultlang");

	if (lang == QLocale::system()) {
		file.remove();
		return;
	}

	QDir d;
	d.mkpath(dir);
	if (file.open(QIODevice::WriteOnly)) {
		file.write(lang.name().toUtf8());
	}
}

bool XCA_application::event(QEvent *ev)
{
	if (ev->type() == QEvent::FileOpen) {
		QStringList l;
		l << static_cast<QFileOpenEvent *>(ev)->file();
		emit openFiles(l);
		return true;
	}
	return QApplication::event(ev);
}
int usage_extract(char *argv[])
{
	fprintf(stderr,
		"Usage: %s %s <database> <type> <name>\n"
		"  database : the filename of the database\n"
		"  type     : one of 'crl' 'cert' 'req'\n",
				argv[0], argv[1]);
	return 1;
}
int main_extract(int argc, char *argv[])
{
	QFile dbfile;
	enum pki_type pkitype = none;
	unsigned char *p;
        db_header_t head;
	QString pkiname, name, fname;
	pki_base *pki;
	BIO *b;

	if (argc != 5) {
		fprintf(stderr, "Wrong number of arguments\n");
		return usage_extract(argv);
	}
	fname = filename2QString(argv[2]);
        dbfile.setFileName(fname);
	if (!dbfile.exists()) {
		fprintf(stderr, "Database '%s' not found\n",argv[2]);
		return usage_extract(argv);
	}
	pkiname = argv[3];
	if (pkiname == "cert")
		pkitype = x509;
	else if (pkiname == "crl")
		pkitype = revokation;
	else if (pkiname == "req")
		pkitype = x509_req;
	else {
		fprintf(stderr, "Invalid type: '%s'\n", argv[3]);
		return usage_extract(argv);
	}
	db mydb(fname);
	name = argv[4];
	if (mydb.find(pkitype, name)) {
		fprintf(stderr, "Item of type %s with name '%s' not found.\n",
			argv[3], argv[4]);
		return usage_extract(argv);
	}
	p = mydb.load(&head);
	if (!p) {
		fprintf(stderr, "Load was empty !");
		return usage_extract(argv);
	}
	name = QString::fromUtf8(head.name);
	switch (pkitype) {
	case x509: pki = new pki_x509(name); break;
	case x509_req: pki = new pki_x509req(name); break;
	case revokation: pki = new pki_crl(name); break;
	default: return usage_extract(argv);
	}
	if (pki->getVersion() < head.version) {
		fprintf(stderr, "Item[%s]: Version %d > known version: %d",
			head.name, head.version, pki->getVersion());
		free(p);
		delete pki;
		return usage_extract(argv);
	}
	pki->setIntName(QString::fromUtf8(head.name));
	try {
		pki->fromData(p, &head);
	} catch (errorEx &err) {
		fprintf(stderr, "Failed to load item from database: %s",
			CCHAR(err.getString()));
	}
	b = BIO_new_fp(stdout, BIO_NOCLOSE);
	pki->pem(b);
	BIO_free(b);
	return 0;
}

int main( int argc, char *argv[] )
{
	int ret = 0, pkictr;
	MainWindow *mw;

	if (QString(argv[1]) == "extract") {
		return main_extract(argc, argv);
	}
	XCA_application a(argc, argv);
	mw = new MainWindow(NULL);
	try {
		a.setMainwin(mw);
		mw->read_cmdline();
		if (mw->exitApp == 0) {
			mw->load_history();
			if (mw->open_default_db() != 2) {
				mw->show();
				ret = a.exec();
			 }
		}
	} catch (errorEx &ex) {
		mw->Error(ex);
	}

	delete mw;
	pkictr =  pki_base::get_pki_counter();
	if (pkictr)
		fprintf(stderr, "PKI Counter (%d)\n", pkictr);

	return ret;
}
