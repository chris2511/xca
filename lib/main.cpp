/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <signal.h>
#include <QApplication>
#include <QTranslator>
#include <QTextCodec>
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QDebug>
#include <openssl/rand.h>
#include "widgets/MainWindow.h"
#include "lib/func.h"
#include "lib/db.h"
#include "lib/main.h"
#include "lib/entropy.h"
#ifdef WIN32
#include <windows.h>
#endif

QLocale XCA_application::lang = QLocale::system();
QFont XCA_application::tableFont;
QList<QLocale> XCA_application::langAvail;

void XCA_application::setMainwin(MainWindow *m)
{
	mainw = m;
}

bool XCA_application::languageAvailable(QLocale l)
{
	return langAvail.contains(l);
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

	langAvail << QLocale::system();
	langAvail << QString("en");
	QDirIterator qmIt(getPrefix(), QStringList() << "*.qm", QDir::Files);
	while (qmIt.hasNext()) {
		XcaTranslator t;
		qmIt.next();
		QString language = qmIt.fileInfo().baseName().mid(4, -1);
		if (t.load(language, "xca", getPrefix()))
			langAvail << QLocale(language);
	}
	setupLanguage(lang);
#ifdef Q_WS_MAC
	QStringList libp = libraryPaths();
	libp.prepend(applicationDirPath() + "/../Plugins");
	setLibraryPaths(libp);
#endif

	tableFont = QFont("Courier", QApplication::font().pointSize()
#if defined(_WIN32) || defined(USE_CYGWIN)
	+1
#else
	+2
#endif
	);
	installEventFilter(this);
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
#if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
		<< "/usr/local/share/qt5/translations/"
		<< "/usr/share/qt5/translations/"
#else
		<< "/usr/local/share/qt4/translations/"
		<< "/usr/share/qt4/translations/"
#endif
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

bool XCA_application::eventFilter(QObject *watched, QEvent *ev)
{
	static int mctr;
	QMouseEvent *me;
	QStringList l;
	int key;

	(void)watched;
	switch (ev->type()) {
	case QEvent::FileOpen:
		l << static_cast<QFileOpenEvent *>(ev)->file();
		mainw->openURLs(l);
		return true;
	case QEvent::MouseMove:
	case QEvent::NonClientAreaMouseMove:
		if (mctr++ > 8) {
			me = static_cast<QMouseEvent *>(ev);
			entropy.add(me->globalX());
			entropy.add(me->globalY());
			mctr = 0;
		}
		break;
	case QEvent::KeyPress:
		key = static_cast<QKeyEvent *>(ev)->key();
		if (key < 0x100) {
			entropy.add(key);
		}
		break;
	default:
		break;
	}
	return false;
}

XCA_application::~XCA_application()
{
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
	Entropy e;

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
		pkitype = revocation;
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
	case revocation: pki = new pki_crl(name); break;
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

char segv_data[1024];

#ifdef WIN32
static LONG CALLBACK w32_segfault(LPEXCEPTION_POINTERS e)
{
	if (e->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
		if (segv_data[0]) {
			XCA_WARN(QString(segv_data));
			abort();
		}
		return EXCEPTION_CONTINUE_EXECUTION;
	} else
		return EXCEPTION_CONTINUE_SEARCH;
}
#else
static void segv_handler_gui(int)
{
	if (segv_data[0])
		XCA_WARN(QString(segv_data));
	abort();
}
#endif

int main( int argc, char *argv[] )
{
	int ret = 0, pkictr;
	MainWindow *mw;

#ifdef WIN32
	SetUnhandledExceptionFilter(w32_segfault);
#else
	signal(SIGSEGV, segv_handler_gui);
#endif

	if (QString(argv[1]) == "extract") {
		return main_extract(argc, argv);
	}
	XCA_application a(argc, argv);
	mw = new MainWindow(NULL);
	try {
		a.setMainwin(mw);
		mw->read_cmdline(argc, argv);
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
	pkictr = pki_base::get_pki_counter();
	if (pkictr)
		fprintf(stderr, "PKI Counter (%d)\n", pkictr);

	return ret;
}
