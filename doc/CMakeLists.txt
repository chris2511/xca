
set(S "${PROJECT_SOURCE_DIR}/doc")
set(D "${PROJECT_BINARY_DIR}/doc")
file(MAKE_DIRECTORY "${D}")

find_program(SPHINX sphinx-build)
find_program(QTCOLLGEN qcollectiongenerator)

set(FILENAMES
	index commandline requests object-ids common-actions database options
	certificates revocationlist changelog introduction privatekey
	step-by-step certificate-input template smartcard miscellaneous
)

foreach(file ${FILENAMES})
  list(APPEND RST_SOURCE "${S}/rst/${file}.rst")
  list(APPEND RST_DEST "${D}/rst/${file}.rst")
  list(APPEND HTML_DEST "${D}/html/${file}.html")
  list(APPEND QTHELP_DEST "${D}/qthelp/${file}.html")
endforeach()

if(SPHINX)
  configure_file(${S}/conf.py.in ${D}/rst/conf.py)
  add_custom_command(
	OUTPUT ${HTML_DEST}
	COMMAND ${SPHINX} -b html ${D}/rst ${D}/html
	DEPENDS "${D}/rst/conf.py" sphinx-src
	COMMENT "Create HTML documentation"
  )
  add_custom_command(
	OUTPUT "${D}/qthelp/xca.qhcp" "${D}/qthelp/xca.qch" ${QTHELP_DEST}
	COMMAND ${SPHINX} -b qthelp ${D}/rst ${D}/qthelp
	DEPENDS "${D}/rst/conf.py" sphinx-src
	COMMENT "Create context sensitive help"
  )
  add_custom_command(
	OUTPUT ${D}/rst/database_schema.sql
	COMMAND ${CMAKE_COMMAND} -E make_directory ${D}/rst/_static
	COMMAND ${CMAKE_COMMAND}
		-D "SRC=${PROJECT_SOURCE_DIR}/lib/database_schema.cpp"
		-D "DST=${D}/rst/database_schema.sql"
		-P "${PROJECT_SOURCE_DIR}/cmake/database_schema.cmake"
	DEPENDS "${PROJECT_SOURCE_DIR}/lib/database_schema.cpp"
	COMMENT "Generating database schema SQL documentation"
  )
  add_custom_command(
	OUTPUT ${D}/rst/COPYRIGHT ${D}/rst/changelog
		${D}/rst/_static/bigcert.png ${RST_DEST}
	COMMAND ${CMAKE_COMMAND} -E make_directory "${D}/rst/_static"
	COMMAND ${CMAKE_COMMAND} -E copy_if_different
				"${PROJECT_SOURCE_DIR}/img/bigcert.png"
				"${D}/rst/_static"
	COMMAND ${CMAKE_COMMAND} -E copy_if_different
				"${PROJECT_SOURCE_DIR}/COPYRIGHT"
				"${PROJECT_SOURCE_DIR}/changelog"
				${RST_SOURCE} ${D}/rst
	DEPENDS "${PROJECT_SOURCE_DIR}/COPYRIGHT"
		"${PROJECT_SOURCE_DIR}/changelog"
		${RST_SOURCE}
	COMMENT "Prepare Sphinx source directory"
  )
  add_custom_command(
	OUTPUT "${D}/rst/arguments.rst"
	COMMAND xcadoc rst "${D}/rst/arguments.rst"
	COMMENT "Generate 'rst' commandline documentation"
  )
  add_custom_target(sphinx-html DEPENDS ${D}/html/index.html)
  add_custom_target(sphinx DEPENDS sphinx-html sphinx-qthelp)
  add_custom_target(sphinx-src
	DEPENDS ${D}/rst/COPYRIGHT ${D}/rst/changelog
		${D}/rst/_static/bigcert.png
		${D}/rst/database_schema.sql
		${D}/rst/arguments.rst
		${RST_DEST}
  )
  list(APPEND APP_RESOURCES ${QTHELP_DEST} "${D}/qthelp/xca.qhc"
         "${D}/qthelp/xca.qch"
  )

  if (UNIX AND NOT APPLE)
    install(FILES ${HTML_DEST}
        DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/${CMAKE_PROJECT_NAME}
  )
  endif()
  if(QTCOLLGEN)
    add_custom_command(
	OUTPUT "${D}/qthelp/xca.qhc"
	COMMAND ${QTCOLLGEN} -o "${D}/qthelp/xca.qhc" "${D}/qthelp/xca.qhcp"
	DEPENDS "${D}/qthelp/xca.qhcp"
	COMMENT "Create context sensitive help index"
    )
    add_custom_target(sphinx-qthelp ALL DEPENDS ${D}/qthelp/xca.qhc)
    target_sources(${CMAKE_PROJECT_NAME} PRIVATE
	 "${QTHELP_DEST}"
	 "${D}/qthelp/xca.qhc"
	 "${D}/qthelp/xca.qch"
    )

  endif()
endif()

if (NOT SPHINX OR NOTQTCOLLGEN)
  add_custom_target(sphinx-qthelp)
endif()

if (NOT WIN32)
  add_custom_command(
	OUTPUT "${D}/xca.1.gz"
	COMMAND cat "${S}/xca.1.head" "${D}/xca.1.options" "${S}/xca.1.tail" | gzip > "${D}/xca.1.gz"
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
    install(FILES "${D}/xca.1.gz"
        DESTINATION ${CMAKE_INSTALL_MANDIR}/man1
    )
  endif()
  add_dependencies(${CMAKE_PROJECT_NAME} manpage)
endif()
