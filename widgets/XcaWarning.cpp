/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2018 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "XcaWarning.h"
#include "lib/func.h"
#include <QApplication>
#include <QClipboard>
#include <QPushButton>
#include <QDebug>
#include <QSqlDatabase>

xcaWarning::xcaWarning(QWidget *w, const QString &txt, QMessageBox::Icon icn)
{
	buttons = QMessageBox::NoButton;
	m = NULL;
	msg = txt;
	icon = icn;

	if (IS_GUI_APP) {
		m = new QMessageBox(icn, XCA_TITLE, txt, buttons, w);
		m->setTextFormat(Qt::PlainText);
		return;
	}
	button_texts[QMessageBox::Ok] = QMessageBox::tr("Ok");
	button_texts[QMessageBox::Close] = QMessageBox::tr("Close");
	button_texts[QMessageBox::Cancel] = QMessageBox::tr("Cancel");
	button_texts[QMessageBox::Apply] = QMessageBox::tr("Apply");
	button_texts[QMessageBox::Yes] = QMessageBox::tr("Yes");
	button_texts[QMessageBox::No] = QMessageBox::tr("No");
}

xcaWarning::~xcaWarning()
{
	delete m;
}

void xcaWarning::setStandardButtons(QMessageBox::StandardButtons b)
{
	buttons = b;
	if (m)
		m->setStandardButtons(b);
}

int xcaWarning::exec()
{
	if (m)
		return m->exec();

	QMap<QMessageBox::Icon, const char *> colors;
	colors[QMessageBox::Information] = COL_CYAN "Information";
	colors[QMessageBox::Warning] = COL_RED "Warning";
	colors[QMessageBox::Critical] = COL_RED "Critical";
	colors[QMessageBox::Question] = COL_BLUE "Question";

	console_write(stdout, QString("%1:" COL_RESET " %2\n")
				.arg(colors[icon]).arg(msg).toUtf8());
	return QMessageBox::Ok;
}

void xcaWarning::addButton(QMessageBox::StandardButton button,
				const QString &text)
{
	if (m) {
		QPushButton *b = m->addButton(button);
		if (b && !text.isEmpty())
			b->setText(text);
	} else {
		buttons |= button;
		if (!text.isEmpty())
			button_texts[button] = text;
	}
}

void xcaWarning::information(const QString &msg)
{
	xcaWarning m(NULL, msg, QMessageBox::Information);
	m.setStandardButtons(QMessageBox::Ok);
	m.exec();
}

void xcaWarning::warning(const QString &msg)
{
	xcaWarning m(NULL, msg, QMessageBox::Warning);
	m.setStandardButtons(QMessageBox::Ok);
	m.exec();
}

bool xcaWarning::yesno(const QString &msg)
{
	xcaWarning m(NULL, msg, QMessageBox::Question);
	m.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
	return m.exec() == QMessageBox::Yes;
}

bool xcaWarning::okcancel(const QString &msg)
{
	xcaWarning m(NULL, msg, QMessageBox::Warning);
	m.setStandardButtons(QMessageBox::Ok | QMessageBox::Cancel);
	return m.exec() == QMessageBox::Ok;
}

void xcaWarning::sqlerror(QSqlError err)
{
	if (!err.isValid())
		err = QSqlDatabase::database().lastError();

	if (err.isValid()) {
		qCritical() << "SQL ERROR:" << err.text();
		XCA_WARN(err.text());
	}
}

void xcaWarning::error(const errorEx &err)
{
	if (err.isEmpty())
		 return;
	QString msg = tr("The following error occurred:") +
			"\n" + err.getString();
	xcaWarning box(NULL, msg);
	box.addButton(QMessageBox::Apply, tr("Copy to Clipboard"));
	box.addButton(QMessageBox::Ok);
	if (box.exec() == QMessageBox::Apply) {
		QClipboard *cb = QApplication::clipboard();
		cb->setText(msg);
		if (cb->supportsSelection())
			cb->setText(msg, QClipboard::Selection);
	}
}
