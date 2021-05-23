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

elseif(WIN32)

  set(QT_USE_QTMAIN TRUE)

endif()

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

if(APPLE)
  if (DEFINED ENV{APPLE_DEVELOPER})
    set(APPLE_CERT_3PARTY_INST "3rd Party Mac Developer Installer: $ENV{APPLE_DEVELOPER}")
    set(APPLE_CERT_3PARTY_APP "3rd Party Mac Developer Application: $ENV{APPLE_DEVELOPER}")
    set(APPLE_CERT_ID_APP "Developer ID Application: $ENV{APPLE_DEVELOPER}")
  endif()
  set_target_properties(${CMAKE_PROJECT_NAME} PROPERTIES
	MACOSX_BUNDLE TRUE
	RESOURCE "${APP_RESOURCES}"
  )
  install(CODE "
    include(BundleUtilities)
    fixup_bundle(\"${CMAKE_BINARY_DIR}/${CMAKE_PROJECT_NAME}.app\" \"\" \"${LIBS_PATH}\")
    verify_app(xca)
  " COMPONENT Runtime)

  set(CPACK_BUNDLE_APPLE_CERT_APP "${APPLE_CERT_ID_APP}")
  set(CPACK_BUNDLE_NAME ${PROJECT_NAME})
  set(CPACK_GENERATOR "DragNDrop;productbuild")

elseif(WIN32)
  set(QT_USE_QTMAIN TRUE)
  set(CPACK_GENERATOR WIX)
else()
  set(CPACK_SOURCE_GENERATOR "TGZ")
  set(CPACK_SOURCE_IGNORE_FILES \\.git/ build/ ".*~$")
  set(CPACK_VERBATIM_VARIABLES YES)
endif()

include(CPack)
