/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2012 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "Help.h"
#include "lib/func.h"

#include <QDebug>
#include <QHelpEngine>

Help::Help() : QWidget(NULL)
{
	setupUi(this);
	setWindowTitle(XCA_TITLE);
	textbox->setSearchPaths(QStringList(getDocDir()));

	helpengine = new QHelpEngineCore(getDocDir() + "/xca.qhc");
}

Help::~Help()
{
	delete helpengine;
}

void Help::display(const QUrl &url)
{
	qDebug() << "URL:" << url.toString() << "Fragment:" << url.fragment();
        textbox->setHtml(QString::fromUtf8( helpengine->fileData(url)));
	textbox->scrollToAnchor(url.fragment());
        show();
}

void Help::content()
{
	display(QUrl("qthelp://org.sphinx.xca/doc/index.html"));
}

void Help::contexthelp(const QString &context)
{
	QMap<QString, QUrl> helpctx(helpengine->linksForIdentifier(context));

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
	qDebug() << "help_ctx" << ctx;
	contexthelp(QString("%1.%1").arg(ctx));
}
