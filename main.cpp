
#include <qapplication.h>
#include "MainWindow.h"


int main( int argc, char *argv[] )
{
    QApplication *a = new QApplication( argc, argv );
    MainWindow *mw = new MainWindow( NULL, "Main Widget");
    mw->setCaption("X Certification Authority"); 
    a->setMainWidget( mw );
    mw->show();
    return a->exec();
}
