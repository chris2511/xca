/****************************************************************************
**
** Copyright (C) 2007 Trolltech ASA. All rights reserved.
**
** This file may be used under the terms of the GNU General Public
** License version 2.0 as published by the Free Software Foundation
** and appearing in the file LICENSE.GPL included in the packaging of
** this file.  Please review the following information to ensure GNU
** General Public Licensing requirements will be met:
** http://www.trolltech.com/products/qt/opensource.html
**
** If you are unsure which license is appropriate for your use, please
** review the following information:
** http://www.trolltech.com/products/qt/licensing.html or contact the
** sales department at sales@trolltech.com.
**
** This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
** WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
**
****************************************************************************/
#include "shared.h"

int main(int argc, char **argv)
{
    QString appBundlePath;
    if (argc > 1)
        appBundlePath = QString::fromLocal8Bit(argv[1]);

    if (argc < 2 || appBundlePath.startsWith("-")) {
        qDebug() << "Usage: macdeployqt app-bundle [-no-plugins] [-dmg]";
        qDebug() << "";
        qDebug() << "macdeployqt creates self-contained application bundles that";
        qDebug() << "contains the Qt frameworks and plugins used by the application.";
        qDebug() << "";
        qDebug() << "Only frameworks in use are copied into the bundle.";
        qDebug() << "Plugins related to a framework are copied in with the";
        qDebug() << "framework. The accessibilty, image formats, and text codec";
        qDebug() << "plugins are always copied, unless \"-no-plugins\" is specified.";
        qDebug() << "";
        qDebug() << "See the \"Deploying an Application on Qt/Mac\" typic in the";
        qDebug() << "documentation for more information about deployment on Mac OS X.";

        return 0;
    }

    if (appBundlePath.endsWith("/"))
        appBundlePath.chop(1);

    DeploymentInfo deploymentInfo  = deployQtFrameworks(appBundlePath);

    bool plugins = true;
    bool dmg = false;

    for (int i = 2; i < argc; ++i) {
        QByteArray argument = QByteArray(argv[i]);
        if (argument == QByteArray("-no-plugins"))
            plugins = false;
        if (argument == QByteArray("-dmg"))
            dmg = true;
    }

    if (plugins) {
        if (deploymentInfo.qtPath.isEmpty()) {
            QString sysroot = getenv("SYSROOT");
            deploymentInfo.pluginPath = sysroot + "/Developer/Applications/Qt/plugins"; // Assume binary package.
        } else
            deploymentInfo.pluginPath = deploymentInfo.qtPath + "/plugins";

        qDebug() << "Deploying plugins from" << deploymentInfo.pluginPath;
        deployPlugins(appBundlePath, deploymentInfo);
        createQtConf(appBundlePath);
    }

    if (dmg) {
        qDebug() << "Creating disk image (.dmg) for" << appBundlePath;
        createDiskImage(appBundlePath);
    }
}

