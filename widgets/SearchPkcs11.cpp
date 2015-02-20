/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2011 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "SearchPkcs11.h"
#include "lib/base.h"
#include "lib/func.h"
#include "lib/pkcs11_lib.h"

#include <QComboBox>
#include <QLineEdit>
#include <QFileDialog>
#include <QPushButton>
#include <QMessageBox>
#include <QStringList>
#include <QFile>

SearchPkcs11::SearchPkcs11(QWidget *parent, QString fname)
	:QDialog(parent)
{
	setupUi(this);
	filename->setText(fname);
	setWindowTitle(XCA_TITLE);

	filename->setText(getLibDir());
	searching = NULL;
}

SearchPkcs11::~SearchPkcs11()
{
	if (searching)
		search->click();
}

void SearchPkcs11::on_fileBut_clicked()
{
	QString s = QFileDialog::getExistingDirectory(this, QString(XCA_TITLE),
		filename->text());

	if (!s.isEmpty()) {
		nativeSeparator(s);
		filename->setText(s);
	}
}

void SearchPkcs11::on_search_clicked()
{
	if (searching) {
		return;
	}
	searching = new searchThread(filename->text(),
		getLibExtensions(),
		subdirs->isChecked());

	liblist->clear();
	connect(searching, SIGNAL(updateLibs(QString)),
		this, SLOT(updateLibs(QString)));
	connect(searching, SIGNAL(updateCurrFile(QString)),
		this, SLOT(updateCurrFile(QString)));
	connect(searching, SIGNAL(finished()),
		this, SLOT(finishSearch()));

	connect(search, SIGNAL(clicked()),
		searching, SLOT(cancelSearch()));

	search->setText("Cancel");
	searching->start();
}

void SearchPkcs11::finishSearch()
{
	search->setText("Start");
	currFile->setText(tr("The following files are possible PKCS#11 libraries"));
	if (!searching)
		return;
	searching->wait(1000);
	delete searching;
	searching = NULL;
}

void SearchPkcs11::buttonPress(QAbstractButton *but)
{
	QList<QListWidgetItem *> libitems;
	QListWidgetItem *lib;

	switch (buttonBox->standardButton(but)) {
	case QDialogButtonBox::Ok:
		accept();
		break;
	default:
	case QDialogButtonBox::Cancel:
		reject();
		break;
	case QDialogButtonBox::Open:
		libitems = liblist->selectedItems();
		foreach(lib, libitems)
			loadItem(lib);
		break;
	}
}

void SearchPkcs11::loadItem(QListWidgetItem *lib)
{
	emit addLib(lib->text());
	delete lib;
}

void SearchPkcs11::updateCurrFile(QString f)
{
	int len = f.length();
	QString reduced = f;
	QFontMetrics fm(currFile->font());

	currFile->setToolTip(f);
	while ((currFile->width() < (fm.width(reduced) -10)) && (len > 0)) {
		len -= 10;
		reduced = compressFilename(f, len);
	}
	currFile->setText(reduced);
	currFile->update();
}

void SearchPkcs11::updateLibs(QString f)
{
	liblist->addItem(new QListWidgetItem(f));
	liblist->update();
}

searchThread::searchThread(QString _dir, QStringList _ext, bool _recursive)
{
	dirname = _dir;
	ext = _ext;
	recursive = _recursive;
	keepOnRunning = true;
}

void searchThread::cancelSearch()
{
	keepOnRunning = false;
}

bool searchThread::checkLib(QString file)
{
	qint64 siz;
	int r = -1;

	QFile qf(file);
	siz = qf.size();
	if (qf.open(QIODevice::ReadOnly)) {
		uchar *p = qf.map(0, siz);
		r = QByteArray::fromRawData((char*)p, siz)
			.indexOf("C_GetFunctionList");
		qf.unmap(p);
		qf.close();
	}
	return r != -1;
}

void searchThread::search(QString mydir)
{
	QDir dir = QDir(mydir);
	QStringList files = dir.entryList(
		QStringList(ext),
		QDir::Files | QDir::Readable);

	while (!files.isEmpty() && keepOnRunning) {
		QString file = files.takeFirst();
		if (file.isEmpty())
			continue;
		file = mydir + QDir::separator() + file;
		emit updateCurrFile(file);
		if (checkLib(file))
			emit updateLibs(file);
	}
	if (recursive && keepOnRunning) {
		QString d;
		QStringList dirs = dir.entryList(QStringList(),
		QDir::AllDirs | QDir::NoDotAndDotDot);

		foreach(d, dirs) {
			if (!keepOnRunning)
				break;
			QString s = mydir +QDir::separator() +d;
			emit updateCurrFile(s);
			search(s);
		}
	}
}
