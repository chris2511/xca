# XCA -- X Certificate and Key Management

[![CMake](https://github.com/chris2511/xca/actions/workflows/cmake.yaml/badge.svg)](https://github.com/chris2511/xca/actions/workflows/cmake.yaml)

## __Release Notes__
 * The latest release is *2.4.0*
 * Most notable changes
 * * Add support for Ed25519 keys
 * * Add commandline support (e.g. generate CRL)
 * Fix a lot of bugs
 * Since version 2 of XCA the database format changed to SQL
   Don't try to open it with older versions of XCA (< 1.4.0).
   They will corrupt the database.
 * Please report issues on github <https://github.com/chris2511/xca/issues>

## __Changelog:__

A detailled changelog can be found here:

<http://hohnstaedt.de/xca/index.php/software/changelog>

## __Documentation__

This application is documented in the *Help* menu and here:

<https://www.hohnstaedt.de/xca/index.php/documentation/manual>

## __Build from Source__

### Dependencies

To build XCA you need:
 - a toolchain
 - cmake: https://cmake.org
 - Qt5: https://www.qt.io
 - OpenSSL: https://www.openssl.org
 - Sphinx-Build: https://www.sphinx-doc.org

### Linux / Unix

 - Install the dependencies
   ```
   sudo apt install build-essential libssl-dev pkg-config qtbase5-dev qttools5-dev-tools libqt5sql5 libqt5help5 cmake qttools5-dev python3-sphinxcontrib.qthelp
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
  brew install openssl qt5 python3 cmake
  pip3 install sphinx
  ```
 - Clone: `git clone https://github.com/chris2511/xca.git`
 - Configure: `cmake -B build xca`
 - Make: `cmake --build build -j5`
 - Build the DMG: `cd build && cpack`
 - Build the PKG: `cd build && cpack -G productbuild`

#### Xcode

 - Install dependencies and clone xca as above
   and additionally install the xcode app
 - `cmake -G Xcode
### Windows

- Install the dependencies
  - Install Python for windows from the store or https://www.python.org/downloads/windows/
  - Install OpenSSL from here: https://slproweb.com/download/Win64OpenSSL-1_1_1m.msi and verify the sha256 from https://github.com/slproweb/opensslhashes/blob/master/win32_openssl_hashes.json
  - To install the Qt libraries, cmake and the MinGW compiler [aqtinstall](https://github.com/miurahr/aqtinstall) is used.
  ```
  pip3 install sphinx aqtinstall
  ```
  Add the PATH shown by pip to your PATH
  ```
  aqt install-qt windows desktop 5.15.2 win64_mingw81
  aqt install-tool windows desktop tool_cmake qt.tools.cmake.win64
  aqt install-tool windows desktop tool_mingw qt.tools.win64_mingw810
  ```
  If 7z is missing, install it from the store.
 - Clone: `git clone https://github.com/chris2511/xca.git`
 - Configure: `cmake -B build -G "MinGW Makefiles" xca`
 - Make: `cmake --build build -j5`
 - Build the MSI installer: `cd build && cpack`

Of course VSCode may be used, too. The MSVC toolchain, however
is no supported, yet.

#### SQL Drivers

Optional for the remote database connections:

 - MySQL: https://github.com/thecodemonkey86/qt_mysql_driver/files/5575769/qsqlmysql.dll_Qt_SQL_driver_5.15.2_MinGW_8.1.0_64-bit.zip

 - PostgreSQL: postgresql-14.1-1-windows-x64.exe
