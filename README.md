# XCA - X Certificate and Key Management

[![CMake](https://github.com/chris2511/xca/actions/workflows/cmake.yaml/badge.svg)](https://github.com/chris2511/xca/actions/workflows/cmake.yaml)

## __Release Notes__

* The latest release is *2.9.0*
* This release fixes some minor issues:
  * Improve remote database support on macosx
  * Do not revoke renewed certificate with same serial
  * Fix default template finding on linux
  * Use latest OpenSSL and Qt releases for the precompiled releases.
* Please report issues on github <https://github.com/chris2511/xca/issues>

## __Changelog:__

A detailed changelog can be found here:

<https://hohnstaedt.de/xca/index.php/software/changelog>

## __Documentation__

This application is documented in the *Help* menu and here:

<https://www.hohnstaedt.de/xca/index.php/documentation/manual>

## __Build from Source__

### Dependencies

To build XCA you need:
 - a toolchain
 - cmake: https://cmake.org
 - Qt5 or Qt6: https://www.qt.io (5.10.1 or higher)
 - OpenSSL: https://www.openssl.org (1.1.1 or higher)
   or libressl-3.6.x
 - Sphinx-Build: https://www.sphinx-doc.org

### Linux / Unix

 - Install the dependencies
   ```
   # Bookworm
   sudo apt install build-essential libssl-dev pkg-config cmake qttools5-dev python3-sphinxcontrib.qthelp
   # Bullseye
   sudo apt install build-essential libssl-dev pkg-config cmake qttools5-dev python3-sphinx
   # Either Qt5
   sudo apt install qtbase5-dev qttools5-dev-tools libqt5sql5 libqt5help5 qttools5-dev
   # Or Qt6
   sudo apt install qt6-base-dev qt6-tools-dev
   ```
 - Clone: `git clone https://github.com/chris2511/xca.git`
 - Configure: `cmake -B build xca`
 - Make: `cmake --build build -j5`
 - Install: `sudo cmake --install build`
 - Or install local and copy later as root: `DESTDIR=DEST cmake --install build --prefix /usr`

### Apple macos

- Install the dependencies
  ```
  xcode-select --install
  brew install openssl@3 qt6 python3 cmake
  pip3 install sphinx
  ```
- Clone: `git clone https://github.com/chris2511/xca.git`
- Configure: `cmake -B build xca`
- Make: `cmake --build build -j5`
- Build the DMG: `cd build && cpack`
- Build the PKG: `cd build && cpack -G productbuild`

XCA can be used with Xcode after initializing the directory with:
`cmake -G Xcode -B .`

### Windows

- Install the dependencies
  - Install Python 3.11 for windows from the store or https://www.python.org/downloads/windows/
  - Install OpenSSL from here: https://slproweb.com/download/Win64OpenSSL-3_1_5.msi and verify the sha256 from https://github.com/slproweb/opensslhashes/blob/master/win32_openssl_hashes.json
  - To install the Qt libraries, cmake and the MinGW compiler [aqtinstall](https://github.com/miurahr/aqtinstall) is used.
    Sphinx is used to generate the documentation
    ```
    pip3 install sphinx aqtinstall
    ```
  - Add the PATH shown by pip to your PATH
  - Install Qt, cmake and the MinGW toolchain
    ```
    aqt install-qt windows desktop 6.6.3 win64_mingw
    aqt install-tool windows desktop tools_mingw90 qt.tools.win64_mingw900
    aqt install-tool windows desktop tools_vcredist qt.tools.vcredist_64
    ```
  - If 7z is missing, install it from the store. `7-Zip File Manager (unofficial)` or from 7-zip.org
  - Install the "vcredist\\vcredist_64.exe"
  - Add cmake, MinGW, OpenSSL and Qt6 to your Path
    ```
    %USERPROFILE%\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.10_qbz5n2kfra8p0\LocalCache\local-packages\Python310\Scripts;
    %USERPROFILE%\AppData\Local\Microsoft\WindowsApps;
    %USERPROFILE%\Tools\CMake_64\bin;
    %USERPROFILE%\Tools\mingw_64\bin;
    %USERPROFILE%\6.6.3\mingw_64\bin;
    ```
  - Create `CMAKE_PREFIX_PATH` environment variable:
    ```
    %USERPROFILE%\6.6.3\mingw_64\lib\cmake
    ```
  - Install `https://wixtoolset.org/releases/` if you want to create the MSI installer

- Clone: `git clone https://github.com/chris2511/xca.git`
- Configure: `cmake -B build -G "MinGW Makefiles" xca`
- Make: `cmake --build build -j5`
- Create the Portable App: `cmake --build build -t install`
- Build the MSI installer (and the Portable App): `cd build ; cpack`

## __SQL Remote Database Drivers__

MySQL plugins are not shipped with QT anymore because of license issues.

### Linux

- Debian: `libqt6sql6-psql` `libqt6sql6-mysql` or `libqt6sql6-odbc`.
- RPM: `libqt6-database-plugin-pgsql` `libqt6-database-plugin-mysql` `libqt6-database-plugin-odbc`

They should pull in all necessary dependencies.

### Apple macos

- **PostgreSQL**: Driver included since XCA 2.9.0
- **ODBC**: It requires the `/usr/local/opt/libiodbc/lib/libiodbc.2.dylib`.
    When installing unixodbc via `brew` the library must be symlinked from
    `/opt/homebrew/Cellar/libiodbc/3.52.16/lib/libiodbc.2.dylib`
- **MariaDB**: Driver included since XCA 2.8.0

### Windows

- **PostgreSQL**: https://www.enterprisedb.com/downloads/postgres-postgresql-downloads (Commandline tools).
  Add the `bin` directory of the Postgres installation directory to your PATH (C:\\Program Files\\PostgreSQL\\16)
- **ODBC**: Use the `ODBC Datasources 64bit app` to configure the SQL Server
- **MariaDB (MySQL)**: Install the Plugin from here: https://github.com/thecodemonkey86/qt_mysql_driver.
  Select the MinGW variant and install it as documented.
