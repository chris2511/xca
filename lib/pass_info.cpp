
#include "pass_info.h"

pass_info::pass_info(QString t, QString d, QWidget *w)
{
	title = t;
	description = d;
	widget = w;
	if (!widget)
		widget = qApp->activeWindow();
	type = tr("Password");
	pixmap = MainWindow::keyImg;
}

void pass_info::setPin()
{
	type = tr("PIN");
	pixmap = MainWindow::scardImg;
}

