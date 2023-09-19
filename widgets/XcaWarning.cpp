/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2018 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "XcaWarning.h"
#include "XcaDialog.h"
#include "lib/func.h"

#include <QApplication>
#include <QClipboard>
#include <QPushButton>
#include <QDebug>
#include <QSqlDatabase>
#include <QTextEdit>

xcaWarningBox::xcaWarningBox(QWidget *w, const QString &txt,
				QMessageBox::Icon icn)
	: QMessageBox(icn, XCA_TITLE, txt, QMessageBox::NoButton, w)
{
	setTextFormat(Qt::PlainText);
}

void xcaWarningBox::addButton(QMessageBox::StandardButton button,
				const QString &text)
{
	QPushButton *b = QMessageBox::addButton(button);
	if (b && !text.isEmpty())
		b->setText(text);
}

int xcaWarningGui::showBox(const QString &txt, QMessageBox::Icon icn,
			QMessageBox::StandardButtons b)
{
	QMessageBox w(icn, XCA_TITLE, txt, b, nullptr);
	return w.exec();
}

void xcaWarningGui::information(const QString &msg)
{
	showBox(msg, QMessageBox::Information, QMessageBox::Ok);
}

void xcaWarningGui::warning(const QString &msg)
{
	showBox(msg, QMessageBox::Warning, QMessageBox::Ok);
}

bool xcaWarningGui::yesno(const QString &msg)
{
	return showBox(msg, QMessageBox::Question,
		QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes;
}

bool xcaWarningGui::okcancel(const QString &msg)
{
	return showBox(msg, QMessageBox::Warning,
		QMessageBox::Ok | QMessageBox::Cancel) == QMessageBox::Ok;
}

void xcaWarningGui::sqlerror(QSqlError err)
{
	qCritical() << "SQL ERROR:" << err.text();
}

void xcaWarningGui::error(const QString &msg)
{
	xcaWarningBox box(NULL, msg);
	box.addButton(QMessageBox::Apply, tr("Copy to Clipboard"));
	box.addButton(QMessageBox::Ok);
	if (box.exec() == QMessageBox::Apply) {
		QClipboard *cb = QApplication::clipboard();
		cb->setText(msg);
		if (cb->supportsSelection())
			cb->setText(msg, QClipboard::Selection);
	}
}

void xcaWarningGui::warningv3(const QString &msg, const extList &el)
{
	QString etext = QString("<h3>") + msg +
		QString("</h3><hr>") + el.getHtml("<br>");

	QTextEdit *textbox = new QTextEdit(etext);
	XcaDialog *d = new XcaDialog(NULL, x509, textbox,
				QString(), QString());
	d->aboutDialog(QPixmap(":certImg"));
	d->exec();
	delete d;
}
