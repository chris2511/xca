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
#ifndef MAC_DEPLOMYMENT_SHARED_H
#define MAC_DEPLOMYMENT_SHARED_H

#include <QString>
#include <QStringList>
#include <QDebug>

class FrameworkInfo
{
public:
    QString frameworkDirectory;
    QString frameworkName;
    QString frameworkPath;
    QString binaryDirectory;
    QString binaryName;
    QString binaryPath;
    QString version;
    QString installName;
    QString deployedInstallName;
    QString sourceFilePath;
    QString destinationDirectory;
};

bool operator==(const FrameworkInfo &a, const FrameworkInfo &b);
QDebug operator<<(QDebug debug, const FrameworkInfo &info);

class ApplicationBundleInfo
{
public:
    QString path;
    QString binaryPath;
};

class DeploymentInfo
{
public:
    QString qtPath;
    QString pluginPath;
    QStringList deployedFrameworks;
};


inline QDebug operator<<(QDebug debug, const ApplicationBundleInfo &info);

void changeQtFrameworks(const QString appPath, const QString &qtPath);
void changeQtFrameworks(const QList<FrameworkInfo> frameworks, const QString &appBinaryPath, const QString &qtPath);

FrameworkInfo parseOtoolLibraryLine(const QString &line);
QString findAppBinary(const QString &appBundlePath);
QList<FrameworkInfo> getQtFrameworks(const QString &path);
QList<FrameworkInfo> getQtFrameworks(const QStringList &otoolLines);
QString copyFramework(const FrameworkInfo &framework, const QString path);
DeploymentInfo deployQtFrameworks(const QString &appBundlePath);
DeploymentInfo deployQtFrameworks(QList<FrameworkInfo> frameworks, const QString &bundlePath, const QString &binaryPath);
void createQtConf(const QString &appBundlePath);
void deployPlugins(const QString &appBundlePath, DeploymentInfo deploymentInfo);
void changeIdentification(const QString &id, const QString &binaryPath);
void changeInstallName(const QString &oldName, const QString &newName, const QString &binaryPath);
QString findAppBinary(const QString &appBundlePath);
void createDiskImage(const QString &appBundlePath);

#endif
