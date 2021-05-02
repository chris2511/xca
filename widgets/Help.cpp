/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2012 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "Help.h"
#include "lib/func.h"

#include <QDebug>
#include <QDialog>
#include <QHelpEngine>
#include <QDialogButtonBox>

Help::Help() : QWidget(NULL)
{
	setupUi(this);
	setWindowTitle(XCA_TITLE);
	textbox->setSearchPaths(QStringList(getDocDir()));
	textbox->setOpenExternalLinks(true);
	textbox->clearHistory();
	helpengine = new QHelpEngineCore(getDocDir() + "/xca.qhc");
}

Help::~Help()
{
	delete helpengine;
}

void Help::display(const QUrl &url)
{
#if QT_VERSION < 0x050000
	QString path = url.path();
	int pos = path.lastIndexOf("/");
	if (pos != -1)
		path = path.mid(pos+1);
	textbox->setSource(QUrl(path));
#else
	textbox->setSource(QUrl(url.fileName()));
#endif
	textbox->scrollToAnchor(url.fragment());
	show();
	raise();
}

void Help::content()
{
	display(QUrl("qthelp://org.sphinx.xca/doc/index.html"));
}

QMap<QString, QUrl> Help::url_by_ctx(const QString &ctx) const
{
	return helpengine->linksForIdentifier(QString("%1.%1").arg(ctx));
}

void Help::contexthelp(const QString &context)
{
	QMap<QString, QUrl> helpctx = url_by_ctx(context);

	if (helpctx.count())
		display(helpctx.constBegin().value());
}

void Help::contexthelp()
{
	QObject *o = sender();
	if (!o)
		return;
	QString ctx = o->property("help_ctx").toString();
	if (ctx.isEmpty())
		return;
	contexthelp(ctx);
}

void Help::register_ctxhelp_button(QDialog *dlg, const QString &help_ctx) const
{
	QDialogButtonBox *buttonBox =
			 dlg->findChild<QDialogButtonBox*>("buttonBox");

	if (!buttonBox || help_ctx.isEmpty())
		return;

	dlg->setWindowModality(Qt::WindowModal);
	buttonBox->addButton(QDialogButtonBox::Help);
	buttonBox->setProperty("help_ctx", QVariant(help_ctx));
	connect(buttonBox, SIGNAL(helpRequested()), this, SLOT(contexthelp()));

	if (url_by_ctx(help_ctx).count() == 0) {
		qWarning() << "Unknown help context: " << help_ctx;
		buttonBox->button(QDialogButtonBox::Help)->setEnabled(false);
	}
}
