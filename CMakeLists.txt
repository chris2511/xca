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
configure_file(doc/conf.py.in sphinx/rst/conf.py)

##### Libraries and executables

add_executable(${CMAKE_PROJECT_NAME} img/imgres.qrc)
add_executable(xcadoc xcadoc.cpp)
target_include_directories(xcadoc PRIVATE
	 "${PROJECT_BINARY_DIR}" "${PROJECT_SOURCE_DIR}/lib")

find_package(OpenSSL REQUIRED)
find_package(Qt5 REQUIRED COMPONENTS Core Widgets Sql Help LinguistTools)

add_subdirectory(lib)
add_subdirectory(widgets)

message(STATUS "OPENSSL ${OPENSSL_VERSION} - ${OPENSSL_LIBRARIES} - ${OPENSSL_INCLUDE_DIR}")
message(STATUS "LTDL_LIB ${LTDL_LIB}")

target_link_libraries(${CMAKE_PROJECT_NAME}
	core widgets core
	OpenSSL::Crypto
	${LTDL_LIB}
	Qt5::Widgets Qt5::Core Qt5::Sql Qt5::Help
)
target_link_libraries(xcadoc core Qt5::Core)

###### Translations

set(TS_FILES
lang/xca_de.ts		lang/xca_ja.ts		lang/xca_sk.ts
lang/xca_es.ts		lang/xca_nl.ts		lang/xca_tr.ts
lang/xca_fr.ts		lang/xca_pl.ts		lang/xca_zh_CN.ts
lang/xca_hr.ts		lang/xca_pt_BR.ts
lang/xca_it.ts		lang/xca_ru.ts
)
qt5_add_translation(QM_FILES ${TS_FILES})
add_custom_target(translations DEPENDS ${QM_FILES})
add_dependencies(${CMAKE_PROJECT_NAME} translations)
target_sources(${CMAKE_PROJECT_NAME} PRIVATE ${QM_FILES})

##### SPHINX Documentation and man pages

include(cmake/sphinx-documentation.cmake)

##### XCA Templates

set(XCA_TEMPLATES misc/CA.xca misc/TLS_server.xca misc/TLS_client.xca)
target_sources(${CMAKE_PROJECT_NAME} PRIVATE ${XCA_TEMPLATES})

##### Text Files ids.txt eku.txt dn.txt

macro(Text_header file)
  add_custom_command(OUTPUT misc/${file}.txt
	COMMAND ${CMAKE_COMMAND} -DFILE=${file} -DSRC="${PROJECT_SOURCE_DIR}"
		-P "${PROJECT_SOURCE_DIR}/cmake/text_header_file.cmake"
	DEPENDS misc/${file}.text
  )
  set_source_files_properties("${PROJECT_SOURCE_DIR}misc/${file}.text"
        PROPERTIES MACOSX_PACKAGE_LOCATION Resources
  )
  list(APPEND TEXT_FILES "${PROJECT_BINARY_DIR}/misc/${file}.txt")
endmacro()

Text_header(dn)
Text_header(eku)
Text_header(oids)
add_custom_target(text_files ALL DEPENDS ${TEXT_FILES})
target_sources(${CMAKE_PROJECT_NAME} PRIVATE ${TEXT_FILES})

install(TARGETS ${CMAKE_PROJECT_NAME}
	BUNDLE DESTINATION .
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
	RESOURCE DESTINATION Resources
)

###############################################
##### Host specific settings

if (APPLE)
  find_library(IOKIT_LIBRARY IOKit)
  find_library(COREFOUNDATION_LIBRARY CoreFoundation)
  target_link_libraries(${CMAKE_PROJECT_NAME}
	${IOKIT_LIBRARY} ${COREFOUNDATION_LIBRARY}
  )
  set(CMAKE_MACOSX_BUNDLE ON)
  set_property(TARGET ${PROJECT_NAME} PROPERTY MACOSX_BUNDLE_INFO_PLIST
		"${PROJECT_SOURCE_DIR}/misc/Info.plist.in")

  set_target_properties(${CMAKE_PROJECT_NAME} PROPERTIES
	MACOSX_BUNDLE TRUE
	RESOURCE "${ICONS};${QM_FILES};${XCA_TEMPLATES};${TEXT_FILES}"
  )
  add_dependencies(${CMAKE_PROJECT_NAME} mac-icons)

  # Note Mac specific extension .app
  set(APPS "\$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/${PROJECT_NAME}.app")

  # Directories to look for dependencies
  set(DIRS "${CMAKE_BINARY_DIR}")

  # Path used for searching by FIND_XXX(), with appropriate suffixes added
  if(CMAKE_PREFIX_PATH)
    foreach(dir ${CMAKE_PREFIX_PATH})
      list(APPEND DIRS "${dir}/bin" "${dir}/lib")
    endforeach()
  endif()

  ###### MAC ICONS
  find_program(ICONUTIL iconutil)
  if(ICONUTIL)
    set(ICONS "${PROJECT_BINARY_DIR}/xca-icons.icns")
    file(GLOB ICON_SRC ${PROJECT_SOURCE_DIR}/img/xca-icons.iconset/*.png)
    add_custom_command(OUTPUT ${ICONS}
	  COMMAND iconutil --convert icns -o ${ICONS}
		  ${PROJECT_SOURCE_DIR}/img/xca-icons.iconset
	  DEPENDS ${ICON_SRC}
    )
    add_custom_target(mac-icons DEPENDS ${ICONS})
    set_source_files_properties(${ICONS}
	  PROPERTIES MACOSX_PACKAGE_LOCATION Resources
    )
    target_sources(${CMAKE_PROJECT_NAME} PRIVATE ${ICONS})
  endif()

  # Append Qt's lib folder which is two levels above Qt5Widgets_DIR
  list(APPEND DIRS "${Qt5Widgets_DIR}/../..")

  include(InstallRequiredSystemLibraries)

  message(STATUS "APPS: ${APPS}")
  message(STATUS "QT_PLUGINS: ${QT_PLUGINS}")
  message(STATUS "DIRS: ${DIRS}")

  install(CODE "include(BundleUtilities)
    fixup_bundle(\"${APPS}\" \"${QT_PLUGINS}\" \"${DIRS}\")")

  set(CPACK_GENERATOR "DRAGNDROP")
  include(CPack)

endif (APPLE)

if (WIN32)
  set(QT_USE_QTMAIN TRUE)
endif (WIN32)

if (UNIX AND NOT APPLE)
install(FILES ${QM_FILES} ${TEXT_FILES} ${XCA_TEMPLATES}
	DESTINATION ${CMAKE_INSTALL_DATADIR}/${CMAKE_PROJECT_NAME}
)
install(FILES misc/xca.desktop
	DESTINATION ${CMAKE_INSTALL_DATADIR}/applications
)
install(FILES misc/xca.xml DESTINATION ${CMAKE_INSTALL_DATADIR}/mime/packages)
install(DIRECTORY "${PROJECT_BINARY_DIR}/qthelp/"
	DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/${CMAKE_PROJECT_NAME}
	FILES_MATCHING PATTERN "*.html" PATTERN "xca.q[hc][ch]"
)
install(FILES "${PROJECT_BINARY_DIR}/xca.1.gz"
	DESTINATION ${CMAKE_INSTALL_DATADIR}/man
)
install(FILES img/xca-32x32.xpm
	DESTINATION ${CMAKE_INSTALL_DATADIR}/pixmaps
)

set(ICONDIR ${CMAKE_INSTALL_DATADIR}/icons/hicolor)

macro(Install_PNG size)
  install(FILES img/xca-icons.iconset/icon_${size}.png
	DESTINATION ${ICONDIR}/${size}/apps RENAME xca.png
  )
  install(FILES img/xca-icons.iconset/icon_${size}.png
	DESTINATION ${ICONDIR}/${size}/mimetypes RENAME x-xca-database.png
  )
  install(FILES img/xca-icons.iconset/icon_${size}.png
	DESTINATION ${ICONDIR}/${size}/mimetypes RENAME x-xca-template.png
  )
endmacro()

Install_PNG(16x16)
Install_PNG(32x32)
Install_PNG(48x48)
Install_PNG(64x64)
Install_PNG(16x16)
endif()
