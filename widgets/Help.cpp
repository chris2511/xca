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
#if (QT_VERSION >= QT_VERSION_CHECK(5, 15, 0))
#include <QHelpLink>
#endif

Help::Help() : QWidget(NULL)
{
	setupUi(this);
	setWindowTitle(XCA_TITLE);
	textbox->setSearchPaths(QStringList(getDocDir()));
	textbox->setOpenExternalLinks(true);
	textbox->clearHistory();
	if (!getDocDir().isEmpty())
		helpengine = new QHelpEngineCore(getDocDir() + "/xca.qhc");
}

Help::~Help()
{
	delete helpengine;
}

void Help::display(const QUrl &url)
{
	textbox->setSource(QUrl(url.fileName()));
	textbox->scrollToAnchor(url.fragment());
	show();
	raise();
}

void Help::content()
{
	display(QUrl("qthelp://org.sphinx.xca/doc/index.html"));
}

QList<QUrl> Help::url_by_ctx(const QString &ctx) const
{
	if (!helpengine)
		return QList<QUrl>();
#if (QT_VERSION >= QT_VERSION_CHECK(5, 15, 0))
	QList<QUrl> l;
	foreach(QHelpLink hl,
			helpengine->documentsForIdentifier(QString("%1.%1").arg(ctx)))
	{
		l << hl.url;
	}
	return l;
#else
	return helpengine->linksForIdentifier(QString("%1.%1").arg(ctx)).values();
#endif
}

void Help::contexthelp(const QString &context)
{
	QList<QUrl> helpctx = url_by_ctx(context);

	if (helpctx.count())
		display(helpctx.at(0));
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

void Help::changeEvent(QEvent *event)
{
	if (event->type() == QEvent::LanguageChange)
		retranslateUi(this);
}
