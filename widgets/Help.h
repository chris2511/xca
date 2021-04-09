/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2021 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __HELP_H
#define __HELP_H

#include "ui_Help.h"

#include <QDialog>

class QHelpEngineCore;

class Help: public QWidget, public Ui::Help
{
	Q_OBJECT

	QHelpEngineCore *helpengine;
	void display(const QUrl &url);

   public:
	Help();
	~Help();
	void register_ctxhelp_button(QDialog *dlg,
					const QString &help_ctx) const;
	QMap<QString, QUrl> url_by_ctx(const QString &ctx) const;

   public slots:
	void contexthelp();
	void contexthelp(const QString &context);
	void content();

};
#endif
