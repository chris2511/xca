
find_program(SPHINX sphinx-build)
find_program(QTCOLLGEN qcollectiongenerator)

set(RST_FILES
rst/index.rst rst/commandline.rst rst/requests.rst rst/object-ids.rst
rst/common-actions.rst rst/database.rst rst/options.rst rst/certificates.rst
rst/revocationlist.rst rst/changelog.rst rst/introduction.rst
rst/privatekey.rst rst/step-by-step.rst rst/certificate-input.rst
rst/template.rst rst/smartcard.rst rst/miscellaneous.rst
)

if(SPHINX AND QTCOLLGEN)
  configure_file(conf.py.in rst/conf.py)
  add_custom_command(
	OUTPUT html/index.html
	COMMAND ${SPHINX} -b html rst html
	DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/rst/conf.py" sphinx-src
	COMMENT "Create HTML documentation"
  )
  add_custom_command(
	OUTPUT qthelp/xca.qhcp
	COMMAND ${SPHINX} -b qthelp rst qthelp
	DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/rst/conf.py" sphinx-src
	COMMENT "Create context sensitive help"
  )
  add_custom_command(
	OUTPUT qthelp/xca.qhc
	COMMAND ${QTCOLLGEN} -o qthelp/xca.qhc qthelp/xca.qhcp
	DEPENDS qthelp/xca.qhcp
	COMMENT "Create context sensitive help index"
  )
  add_custom_command(
	OUTPUT rst/database_schema.sql
	COMMAND ${CMAKE_COMMAND} -E make_directory rst/_static
	COMMAND ${CMAKE_COMMAND}
		-D "SRC=${PROJECT_SOURCE_DIR}/widgets/database_schema.cpp"
		-D "DST=rst/database_schema.sql"
		-P "${PROJECT_SOURCE_DIR}/cmake/database_schema.cmake"
	DEPENDS "${PROJECT_SOURCE_DIR}/widgets/database_schema.cpp"
	COMMENT "Generating database schema SQL documentation"
  )
  add_custom_command(
	OUTPUT rst/COPYRIGHT rst/changelog
                rst/_static/bigcert.png rst
	COMMAND ${CMAKE_COMMAND} -E make_directory rst/_static
	COMMAND ${CMAKE_COMMAND} -E copy_directory
				"${PROJECT_SOURCE_DIR}/doc/rst" rst
	COMMAND ${CMAKE_COMMAND} -E copy_if_different
				"${PROJECT_SOURCE_DIR}/COPYRIGHT"
				"${PROJECT_SOURCE_DIR}/changelog"
				rst
	DEPENDS "${PROJECT_SOURCE_DIR}/COPYRIGHT"
		"${PROJECT_SOURCE_DIR}/changelog"
		${RST_FILES}
	COMMENT "Prepare Sphinx source directory"
  )
  add_custom_command(
	OUTPUT rst/arguments.rst
	COMMAND xcadoc rst rst/arguments.rst
	COMMENT "Generate 'rst' commandline documentation"
  )
  add_custom_target(sphinx-html DEPENDS html/index.html)
  add_custom_target(sphinx-qthelp ALL DEPENDS qthelp/xca.qhc)
  add_custom_target(sphinx DEPENDS sphinx-html sphinx-qthelp)
  add_custom_target(sphinx-src
	DEPENDS rst/COPYRIGHT rst/changelog
		rst/_static/bigcert.png rst
		rst/database_schema.sql
		rst/arguments.rst
  )
  file(GLOB HTML_FILES "${CMAKE_CURRENT_BINARY_DIR}/qthelp/*.html"
                        "${CMAKE_CURRENT_BINARY_DIR}/qthelp/xca.q[hc][ch]")
  list(APPEND APP_RESOURCES ${HTML_FILES})
  set(APP_RESOURCES ${APP_RESOURCES} PARENT_SCOPE)
  target_sources(${CMAKE_PROJECT_NAME} PRIVATE ${HTML_FILES})
  install(FILES ${HTML_FILES}
        DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/${CMAKE_PROJECT_NAME}
  )
else()
  add_custom_target(sphinx-qthelp)
endif()

if (NOT WIN32)
  add_custom_command(
	OUTPUT xca.1.gz
	COMMAND sh -c 'cat
		"${CMAKE_CURRENT_SOURCE_DIR}/xca.1.head"
		xca.1.options
		"${CMAKE_CURRENT_SOURCE_DIR}/xca.1.tail" | gzip > xca.1.gz'
	DEPENDS xca.1.head xca.1.tail
		"${CMAKE_CURRENT_BINARY_DIR}/xca.1.options"
	COMMENT "Compiling man page"
  )
  add_custom_command(
	OUTPUT xca.1.options
	COMMAND xcadoc man xca.1.options
	COMMENT "Generate 'man' commandline documentation"
  )
  add_custom_target(manpage ALL DEPENDS xca.1.gz)
  install(FILES "${CMAKE_CURRENT_BINARY_DIR}/xca.1.gz"
        DESTINATION ${CMAKE_INSTALL_MANDIR}/man1
  )
  add_dependencies(${CMAKE_PROJECT_NAME} manpage)
endif()
