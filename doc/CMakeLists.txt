
set(S ${PROJECT_SOURCE_DIR}/doc)
set(D ${PROJECT_BINARY_DIR}/doc)
set(RST ${D}/rst-build)

file(MAKE_DIRECTORY ${RST})

find_program(SPHINX sphinx-build)
find_package(Qt6 QUIET OPTIONAL_COMPONENTS ToolsTools)

set(FILENAMES
    index commandline requests object-ids common-actions database options
    certificates revocationlist changelog introduction privatekey
    step-by-step certificate-input template smartcard miscellaneous
)

foreach(file ${FILENAMES})
  list(APPEND RST_SOURCE ${S}/rst/${file}.rst)
  list(APPEND RST_DEST ${RST}/${file}.rst)
  list(APPEND HTML_DEST ${D}/html/${file}.html)
  list(APPEND HTML_FILE ${file}.html)
  list(APPEND QTHELP_DEST ${D}/qthelp/${file}.html)
endforeach()

foreach(doc ${HTML_FILE} xca.qhc)
  string(REPLACE "-" "" id ${doc})
  guid(${doc})
  list(APPEND DOC_COMPREFS "  <ComponentRef Id=\"Csphinx.${id}\"/>\n")
  list(APPEND DOC_COMPS "  <Component Id=\"Csphinx.${id}\" Guid=\"${GUID}\">
    <File Id=\"sphinx.${id}\" Source=\"${D}/qthelp/${doc}\" KeyPath=\"yes\"/>
  </Component>\n")
endforeach()

string(APPEND WIX_DOC_CONTENT
"<DirectoryRef Id=\"html\">\n" ${DOC_COMPS} "</DirectoryRef>\n"
"<ComponentGroup Id=\"GroupDocumentation\">\n" ${DOC_COMPREFS} "</ComponentGroup>"
)

WixFile(${D}/documentation.wxs ${WIX_DOC_CONTENT})

if(SPHINX)
  add_custom_command(
    OUTPUT ${RST}/database_schema.sql
    COMMAND ${CMAKE_COMMAND} -E make_directory ${RST}/_static
    COMMAND ${CMAKE_COMMAND}
        -D SRC=${PROJECT_SOURCE_DIR}/lib/database_schema.cpp
        -D DST=${RST}/database_schema.sql
        -P ${PROJECT_SOURCE_DIR}/cmake/database_schema.cmake
    DEPENDS ${PROJECT_SOURCE_DIR}/lib/database_schema.cpp
    COMMENT "Generating database schema SQL documentation"
  )
  add_custom_command(
    OUTPUT ${D}/rst.stamp
    BYPRODUCTS ${RST}/COPYRIGHT ${RST}/changelog ${RST_DEST}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${RST}/_static
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${PROJECT_SOURCE_DIR}/img/bigcert.png
            ${RST}/_static
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${PROJECT_SOURCE_DIR}/COPYRIGHT
            ${PROJECT_SOURCE_DIR}/changelog
            ${RST_SOURCE} ${RST}
    COMMAND ${CMAKE_COMMAND} -E touch ${D}/rst.stamp
    DEPENDS ${PROJECT_SOURCE_DIR}/COPYRIGHT
            ${PROJECT_SOURCE_DIR}/changelog
            ${RST_SOURCE}
    COMMENT "Prepare Sphinx source directory"
  )
  add_custom_command(
    OUTPUT ${RST}/arguments.rst
    DEPENDS xcadoc
    COMMAND xcadoc rst ${RST}/arguments.rst
    COMMENT "Generate 'rst' commandline documentation"
  )
  target_sources(${CMAKE_PROJECT_NAME} PRIVATE ${HTML_DEST})
  foreach(EXPORT_TOPIC x509 x509-clp key key-clp request revocation)
    set(EXPORT_DEST ${RST}/export-${EXPORT_TOPIC}.rst)
    add_custom_command(
      OUTPUT ${EXPORT_DEST}
      DEPENDS xcaexport
      COMMAND xcaexport ${EXPORT_TOPIC} ${EXPORT_DEST}
      COMMENT "Generate '${EXPORT_TOPIC}' export documentation"
    )
    list(APPEND EXPORT_TOPICS ${EXPORT_DEST})
  endforeach()

  configure_file(${S}/conf.py.in ${RST}/conf.py)
  set(SPHINX_SRC ${D}/rst.stamp ${RST}/database_schema.sql
      ${RST}/arguments.rst ${RST}/conf.py ${EXPORT_TOPICS}
  )
  add_custom_target(sphinx-src DEPENDS ${SPHINX_SRC})

  add_custom_command(
    OUTPUT ${HTML_DEST}
    COMMAND ${SPHINX} -q -b html ${RST} ${D}/html
    DEPENDS sphinx-src ${SPHINX_SRC}
    COMMENT "Create HTML documentation"
  )
  add_custom_target(sphinx-html DEPENDS ${HTML_DEST})
  add_dependencies(${CMAKE_PROJECT_NAME} sphinx-html)

  add_custom_command(
    OUTPUT ${D}/qthelp/xca.qhcp ${D}/qthelp/xca.qhp ${QTHELP_DEST}
    COMMAND ${SPHINX} -q -b qthelp ${RST} ${D}/qthelp
    DEPENDS sphinx-src ${SPHINX_SRC}
    COMMENT "Create context sensitive help"
  )

  if (UNIX)
    if (APPLE)
      execute_process(COMMAND ln -fs .doc/html/index.html ${D}/manual.html)
      install(FILES ${D}/manual.html DESTINATION .)
      set(HTML_INSTALL_DEST .doc/html)
      install(DIRECTORY ${D}/html DESTINATION .doc PATTERN ".*" EXCLUDE)
    else()
      install(DIRECTORY ${D}/html/ DESTINATION ${CMAKE_INSTALL_DOCDIR}
          PATTERN ".*" EXCLUDE
      )
    endif()
  endif()

  if (QT_VERSION VERSION_LESS 5.12.0)
    if (TARGET ${QT}::qcollectiongenerator)
      set(QHELPGEN $<TARGET_FILE:${QT}::qcollectiongenerator>)
    endif()
  else()
    if(TARGET ${QT}::qhelpgenerator)
      set(QHELPGEN $<TARGET_FILE:${QT}::qhelpgenerator>)
    endif()
  endif()
  if(QHELPGEN)
    set(QTHELP_IDX ${D}/qthelp/xca.qhc)
    add_custom_command(
      OUTPUT ${QTHELP_IDX}
      COMMAND ${QHELPGEN} -s ${D}/qthelp/xca.qhcp
      DEPENDS ${D}/qthelp/xca.qhcp ${D}/qthelp/xca.qhp ${QTHELP_DEST}
      COMMENT "Create context sensitive help index"
    )
    add_custom_target(sphinx-qtcollgen DEPENDS ${QTHELP_IDX})
    target_sources(${CMAKE_PROJECT_NAME} PRIVATE ${QTHELP_DEST} ${QTHELP_IDX})
    add_dependencies(${CMAKE_PROJECT_NAME} sphinx-qtcollgen)
    list(APPEND APP_RESOURCES ${QTHELP_DEST} ${QTHELP_IDX})

    if (UNIX AND NOT APPLE)
        install(FILES ${QTHELP_DEST} ${QTHELP_IDX}
                DESTINATION ${CMAKE_INSTALL_DATADIR}/${CMAKE_PROJECT_NAME}/html
        )
    elseif (WIN32)
        install(FILES ${QTHELP_DEST} ${QTHELP_IDX}
                DESTINATION ${RUNTIME_DEST}/html
        )
    endif()

  else()
    message(WARNING "Application 'qhelpgenerator' not found. In-app documentation disabled.")
  endif()
else(SPHINX)
  message(WARNING "sphinx-build binary not found. Documentation generation disabled")
endif(SPHINX)

if (NOT WIN32)
  add_custom_command(
    OUTPUT "${D}/xca.1.gz"
    COMMAND cat "${S}/xca.1.head" "${D}/xca.1.options" "${S}/xca.1.tail" | gzip -n9 > "${D}/xca.1.gz"
    DEPENDS "${S}/xca.1.head" "${S}/xca.1.tail"
            "${D}/xca.1.options"
    COMMENT "Compiling man page"
  )
  add_custom_command(
    OUTPUT "${D}/xca.1.options"
    COMMAND xcadoc man "${D}/xca.1.options"
    COMMENT "Generate 'man' commandline documentation"
  )
  add_custom_target(manpage ALL DEPENDS ${D}/xca.1.gz)
  if (NOT APPLE)
    install(FILES "${D}/xca.1.gz" DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)
  endif()
  add_dependencies(${CMAKE_PROJECT_NAME} manpage)
endif()
