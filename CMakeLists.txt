cmake_minimum_required(VERSION 3.12.0)

project(xca
	DESCRIPTION "X Certificate and Key management"
	HOMEPAGE_URL http://xca.hohnstaedt.de
	LANGUAGES CXX
)

file(READ VERSION.txt ver)
string(REGEX MATCH "([0-9\.]*)" _ ${ver})
set(PROJECT_VERSION ${CMAKE_MATCH_1})

include(GNUInstallDirs)

##### Git command to tweak the version and commit hash
include(cmake/git_version.cmake)

##### Build specifications

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_OSX_DEPLOYMENT_TARGET 10.13)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC_SEARCH_PATHS "${PROJECT_SOURCE_DIR}/ui")
set(CMAKE_AUTOUIC ON)
add_compile_definitions(OPENSSL_SUPPRESS_DEPRECATED)

configure_file(local.h.in local.h)

##### Libraries and executables

add_executable(${CMAKE_PROJECT_NAME} img/imgres.qrc ${PROJECT_BINARY_DIR}/local.h)
add_executable(xcadoc ${PROJECT_BINARY_DIR}/local.h)

include_directories(${PROJECT_BINARY_DIR} ${PROJECT_SOURCE_DIR})

set(PSQL_BINDIR "")
set(MYSQL_BINDIR "")

if (APPLE)
  execute_process(COMMAND brew --prefix OUTPUT_STRIP_TRAILING_WHITESPACE
                  OUTPUT_VARIABLE BREW_PREFIX ERROR_QUIET)
  # Preset the default brew paths....
  if (NOT CMAKE_PREFIX_PATH)
    set(CMAKE_PREFIX_PATH ${BREW_PREFIX}/opt/qt@5/)
  endif()
  if (NOT OPENSSL_ROOT_DIR)
    set(OPENSSL_ROOT_DIR ${BREW_PREFIX}/opt/openssl@1.1)
  endif()
elseif(WIN32)
  if (NOT CMAKE_PREFIX_PATH)
    set(CMAKE_PREFIX_PATH "C:/Qt/5.15.2/mingw81_64/")
  endif()
  if (NOT OPENSSL_ROOT_DIR)
    set(OPENSSL_ROOT_DIR $ENV{PROGRAMFILES}/OpenSSL-Win64)
  endif()
  set(PSQL_BINDIR $ENV{PROGRAMFILES}/PostgreSQL/14/bin
                  CACHE PATH "PostgreSQL installation directory for the MSI installer")
  set(MYSQL_BINDIR $ENV{PROGRAMFILES}/qsqlmysql.dll_Qt_SQL_driver_5.15.2_MinGW_8.1.0_64-bit/${CMAKE_BUILD_TYPE}
                  CACHE PATH "MySQL installation directory for the MSI installer")
  if (NOT EXISTS ${PSQL_BINDIR})
    set(PSQL_BINDIR "")
  endif()
  if (NOT EXISTS ${MYSQL_BINDIR})
    set(MYSQL_BINDIR "")
  endif()
  file(TO_CMAKE_PATH $ENV{WINDIR}/system32 SYSTEM32)
endif()
file(TO_CMAKE_PATH "${OPENSSL_ROOT_DIR}" OPENSSL_ROOT_DIR)
file(TO_CMAKE_PATH "${PSQL_BINDIR}" PSQL_BINDIR)
file(TO_CMAKE_PATH "${MYSQL_BINDIR}" MYSQL_BINDIR)

find_package(OpenSSL REQUIRED)
find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Core)
set(QT Qt${QT_VERSION_MAJOR})
find_package(${QT} REQUIRED COMPONENTS Core Widgets Sql Help LinguistTools)
message(STATUS "Using ${QT} with version ${QT_VERSION}")

get_target_property(qmake_executable ${QT}::qmake IMPORTED_LOCATION)
get_target_property(core_libdir ${QT}::Core IMPORTED_LOCATION)
get_filename_component(_qt_bin_dir "${qmake_executable}" DIRECTORY)
find_program(MACDEPLOYQT_EXECUTABLE macdeployqt HINTS "${_qt_bin_dir}")
find_program(WINDEPLOYQT_EXECUTABLE windeployqt HINTS "${_qt_bin_dir}")

if (NOT OPENSSL_ROOT_DIR)
  get_filename_component(OPENSSL_ROOT_DIR ${OPENSSL_INCLUDE_DIR} DIRECTORY)
endif()

target_link_libraries(${CMAKE_PROJECT_NAME}
	OpenSSL::Crypto
	${QT}::Widgets ${QT}::Core ${QT}::Sql ${QT}::Help
)
target_link_libraries(xcadoc
	OpenSSL::Crypto
	${QT}::Widgets ${QT}::Core ${QT}::Sql ${QT}::Help
)

if (APPLE)

  find_library(IOKIT_LIBRARY IOKit)
  find_library(COREFOUNDATION_LIBRARY CoreFoundation)
  target_link_libraries(${CMAKE_PROJECT_NAME}
	${IOKIT_LIBRARY} ${COREFOUNDATION_LIBRARY}
  )
  set(CMAKE_MACOSX_BUNDLE ON)

  # Avoid bin/ sub-directory in DMG
  set(RUNTIME_DEST .)

elseif(WIN32)

  set(RUNTIME_DEST ${CMAKE_PROJECT_NAME}-portable-${PROJECT_VERSION})

else()

  set(RUNTIME_DEST ${CMAKE_INSTALL_BINDIR})

endif()

macro(guid content)
  string(
    UUID GUID NAMESPACE f243d4ea-d51d-42fc-a3c0-4eb186c55d34
    NAME ${content} TYPE SHA1
  )
endmacro()

macro(WixFile filename content)
  file(WRITE ${filename} "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<Wix xmlns=\"http://schemas.microsoft.com/wix/2006/wi\">\n<Fragment>\n"
    ${content}
    "\n</Fragment>\n</Wix>")
endmacro()

##### Sub directories

add_subdirectory(lib)
add_subdirectory(widgets)

include(misc/CMakeLists.txt)
include(lang/CMakeLists.txt)
include(doc/CMakeLists.txt)
include(img/CMakeLists.txt)

install(TARGETS ${CMAKE_PROJECT_NAME}
	RESOURCE DESTINATION Resources
	BUNDLE DESTINATION .
	RUNTIME DESTINATION ${RUNTIME_DEST}
)

set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")

###############################################
##### Host specific settings

if(APPLE)
  set_target_properties(${CMAKE_PROJECT_NAME} PROPERTIES
	MACOSX_BUNDLE TRUE
	XCODE_ATTRIBUTE_INSTALL_PATH /Applications
	XCODE_ATTRIBUTE_SKIP_INSTALL No
	RESOURCE "${APP_RESOURCES}"
  )
  get_target_property(qmake_executable ${QT}::qmake IMPORTED_LOCATION)
  get_filename_component(_qt_bin_dir "${qmake_executable}" DIRECTORY)
  find_program(MACDEPLOYQT_EXECUTABLE macdeployqt HINTS ${_qt_bin_dir})

  add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${MACDEPLOYQT_EXECUTABLE} $<TARGET_FILE_DIR:${PROJECT_NAME}>/../..
        -always-overwrite
    COMMENT "Running macdeployqt..."
  )
  if (DEFINED ENV{APPLE_DEVELOPER_HASH})
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
      COMMAND codesign --deep --signature-size=96000 --options=runtime --timestamp
                --force -s "$ENV{APPLE_DEVELOPER_HASH}"
		$<TARGET_FILE_DIR:${PROJECT_NAME}>/../..
      COMMENT "Running codesign for $ENV{APPLE_DEVELOPER} ..."
    )
  endif()

  set(CPACK_BUNDLE_NAME ${PROJECT_NAME})
  set(CPACK_GENERATOR "DragNDrop") #;productbuild")

elseif(WIN32)
  add_custom_command(TARGET ${CMAKE_PROJECT_NAME} POST_BUILD
    COMMAND ${WINDEPLOYQT_EXECUTABLE} $<TARGET_FILE:${PROJECT_NAME}>
        --dir ${CMAKE_BINARY_DIR} --compiler-runtime
    COMMENT "Running windeployqt on ${CMAKE_PROJECT_NAME} ..."
  )
  add_custom_command(TARGET xcadoc POST_BUILD
    COMMAND ${WINDEPLOYQT_EXECUTABLE} $<TARGET_FILE:xcadoc>
        --dir ${CMAKE_BINARY_DIR} --no-translations
    COMMENT "Running windeployqt on xcadoc ..."
  )
  set(QT_USE_QTMAIN TRUE)
  set(CPACK_GENERATOR WIX)
  set(CPACK_PACKAGE_VENDOR "Christian Hohnstädt")
  set(CPACK_WIX_TEMPLATE "${PROJECT_SOURCE_DIR}/misc/xca.wxs")
  set(CPACK_WIX_UPGRADE_GUID "23fdacfe-3ef8-45b4-81e8-b0c90244c217")
  set(CPACK_WIX_UI_BANNER "${PROJECT_SOURCE_DIR}/img/banner.bmp")
  set(CPACK_WIX_UI_DIALOG "${PROJECT_SOURCE_DIR}/img/dialog.bmp")
  set(CPACK_WIX_LICENSE_RTF "${PROJECT_SOURCE_DIR}/misc/copyright.rtf")
  set(CPACK_WIX_EXTRA_SOURCES
     ${CMAKE_BINARY_DIR}/language.wxs
     ${CMAKE_BINARY_DIR}/doc/documentation.wxs
     ${CMAKE_BINARY_DIR}/misc/misc.wxs
     ${CMAKE_BINARY_DIR}/misc/dynamic.wxs
     )
  target_link_options(${CMAKE_PROJECT_NAME} PRIVATE -mwindows -MD)
  install(DIRECTORY
	  ${CMAKE_BINARY_DIR}/platforms
	  ${CMAKE_BINARY_DIR}/sqldrivers
	  ${CMAKE_BINARY_DIR}/styles
	  DESTINATION ${RUNTIME_DEST}
  )
  install(FILES ${CMAKE_BINARY_DIR}/${QT}Core.dll
		${CMAKE_BINARY_DIR}/${QT}Gui.dll
		${CMAKE_BINARY_DIR}/${QT}Help.dll
		${CMAKE_BINARY_DIR}/${QT}Sql.dll
		${CMAKE_BINARY_DIR}/${QT}Widgets.dll
		${CMAKE_BINARY_DIR}/libgcc_s_seh-1.dll
		${CMAKE_BINARY_DIR}/libstdc++-6.dll
		${CMAKE_BINARY_DIR}/libwinpthread-1.dll
		${SYSTEM32}/vcruntime140.dll
		${OPENSSL_ROOT_DIR}/bin/libcrypto-1_1-x64.dll
	  DESTINATION ${RUNTIME_DEST}
  )
  install(CODE "execute_process(COMMAND cmake -E chdir \${CMAKE_INSTALL_PREFIX} tar cvf ${RUNTIME_DEST}.zip --format=zip -- ${RUNTIME_DEST})")
  set(CMAKE_INSTALL_PREFIX ${CMAKE_BINARY_DIR})

else()
  if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX /usr/local CACHE PATH
        "Default installation directory" FORCE)
  endif()
  message(STATUS "PREFIX: " ${CMAKE_INSTALL_PREFIX})
  set(CPACK_SOURCE_GENERATOR "TGZ")
  set(CPACK_SOURCE_IGNORE_FILES \\.git/ build/ ".*~$")
  set(CPACK_VERBATIM_VARIABLES YES)
endif()

include(CPack)
