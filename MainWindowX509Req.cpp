#include "MainWindow.h"


void MainWindow::newX509Req()
{
	NewX509Req_UI *dlg = new NewX509Req_UI(this,0,true,0);
	dlg->keyList->insertStringList(keys->getPrivateDesc());
	dlg->exec();
}
