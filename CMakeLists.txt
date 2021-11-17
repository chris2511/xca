cmake_minimum_required(VERSION 3.9.0)

project(xca
	DESCRIPTION "X Certificate and Key management"
	HOMEPAGE_URL http://xca.hohnstaedt.de
	LANGUAGES CXX
)

file(READ VERSION ver)
string(REGEX MATCH "([0-9\.]*)" _ ${ver})
set(PROJECT_VERSION ${CMAKE_MATCH_1})

include(GNUInstallDirs)

##### Git command to tweak the version and commit hash
include(cmake/git_version.cmake)

##### Build specifications

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_OSX_DEPLOYMENT_TARGET "10.13")
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC_SEARCH_PATHS "${PROJECT_SOURCE_DIR}/ui")
set(CMAKE_AUTOUIC ON)

configure_file(local.h.in local.h)

##### Libraries and executables

add_executable(${CMAKE_PROJECT_NAME} img/imgres.qrc)
add_executable(xcadoc xcadoc.cpp)
target_include_directories(xcadoc PRIVATE "${PROJECT_SOURCE_DIR}/lib")

find_package(OpenSSL REQUIRED)
find_package(Qt5 REQUIRED COMPONENTS Core Widgets Sql Help LinguistTools)

get_filename_component(OPENSSL_ROOT_DIR ${OPENSSL_INCLUDE_DIR} DIRECTORY)
set(PSQL_BINDIR "C:/Program Files/PostgreSQL/14/bin")
set(MYSQL_BINDIR "C:/Program Files/qsqlmysql.dll_Qt_SQL_driver_5.15.2_MinGW_8.1.0_64-bit/${CMAKE_BUILD_TYPE}")
if (NOT EXISTS ${PSQL_BINDIR})
  set(PSQL_BINDIR "")
endif()
if (NOT EXISTS ${MYSQL_BINDIR})
  set(MYSQL_BINDIR "")
endif()

target_link_libraries(${CMAKE_PROJECT_NAME}
	core widgets core
	OpenSSL::Crypto
	${LTDL_LIB}
	Qt5::Widgets Qt5::Core Qt5::Sql Qt5::Help
)
target_link_libraries(xcadoc core Qt5::Core)

if (APPLE)

  find_library(IOKIT_LIBRARY IOKit)
  find_library(COREFOUNDATION_LIBRARY CoreFoundation)
  target_link_libraries(${CMAKE_PROJECT_NAME}
	${IOKIT_LIBRARY} ${COREFOUNDATION_LIBRARY}
  )
  set(CMAKE_MACOSX_BUNDLE ON)
  set_property(TARGET ${PROJECT_NAME} PROPERTY MACOSX_BUNDLE_INFO_PLIST
		"${PROJECT_SOURCE_DIR}/misc/Info.plist.in")

  ##### Plugins

  get_target_property(sqlplugins Qt5::Sql QT_ALL_PLUGINS_sqldrivers)
  message(STATUS "SQL Plugins ${sqlplugins}")
  foreach(sql ${sqlplugins})
    get_target_property(loc ${sql} LOCATION_${CMAKE_BUILD_TYPE})
    list(APPEND sqlplugin_paths "${loc}")
  endforeach()
  qt5_import_plugins(${CMAKE_PROJECT_NAME} INCLUDE_BY_TYPE sqldrivers)

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
	BUNDLE DESTINATION .
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
	RESOURCE DESTINATION Resources
)

set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")

###############################################
##### Host specific settings

get_target_property(qmake_executable Qt5::qmake IMPORTED_LOCATION)
get_filename_component(_qt_bin_dir "${qmake_executable}" DIRECTORY)
find_program(MACDEPLOYQT_EXECUTABLE macdeployqt HINTS "${_qt_bin_dir}")
find_program(WINDEPLOYQT_EXECUTABLE windeployqt HINTS "${_qt_bin_dir}")

if(APPLE)
  if (DEFINED ENV{APPLE_DEVELOPER})
    set(APPLE_CERT_3PARTY_INST "3rd Party Mac Developer Installer: $ENV{APPLE_DEVELOPER}")
    set(APPLE_CERT_3PARTY_APP "3rd Party Mac Developer Application: $ENV{APPLE_DEVELOPER}")
    set(APPLE_CERT_ID_APP "Developer ID Application: $$APPLE_DEVELOPER")
    set(MACDEPLOYQT_SIGN -codesign=${APPLE_CERT_ID_APP}
			 -timestamp -always-overwrite
    )
  endif()
  set_target_properties(${CMAKE_PROJECT_NAME} PROPERTIES
	MACOSX_BUNDLE TRUE
	RESOURCE "${APP_RESOURCES}"
  )
  add_custom_command(TARGET ${CMAKE_PROJECT_NAME}
    COMMAND "${MACDEPLOYQT_EXECUTABLE}"
        "${CMAKE_BINARY_DIR}/${CMAKE_PROJECT_NAME}.app"
        ${MACDEPLOYQT_SIGN}
    COMMENT "Running macdeployqt..."
  )

  set(CPACK_BUNDLE_NAME ${PROJECT_NAME})
  set(CPACK_GENERATOR "DragNDrop") #;productbuild")

elseif(WIN32)
  add_custom_command(TARGET ${CMAKE_PROJECT_NAME}
    COMMAND "${WINDEPLOYQT_EXECUTABLE}"
        --dir "${CMAKE_BINARY_DIR}"
        "${CMAKE_BINARY_DIR}/${CMAKE_PROJECT_NAME}.exe"
    COMMENT "Running windeployqt..."
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
  string(APPEND CMAKE_CXX_FLAGS "-mwindows")
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
