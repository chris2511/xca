
find_program(SPHINX sphinx-build)
find_program(QTCOLLGEN qcollectiongenerator)

if(SPHINX)
  add_custom_command(
	OUTPUT html/index.html
	COMMAND ${SPHINX} -b html sphinx/rst html
	DEPENDS "${PROJECT_BINARY_DIR}/sphinx/rst/conf.py"
		sphinx-src sphinx/rst/arguments.rst
	COMMENT "Create HTML documentation"
  )
  add_custom_command(
	OUTPUT qthelp/xca.qhcp
	COMMAND ${SPHINX} -b qthelp sphinx/rst qthelp
	DEPENDS "${PROJECT_BINARY_DIR}/sphinx/rst/conf.py"
		sphinx-src sphinx/rst/arguments.rst
	COMMENT "Create context sensitive help"
  )
  add_custom_command(
	OUTPUT qthelp/xca.qhc
	COMMAND ${QTCOLLGEN} -o "${PROJECT_BINARY_DIR}/qthelp/xca.qhc"
		"${PROJECT_BINARY_DIR}/qthelp/xca.qhcp"
	DEPENDS "${PROJECT_BINARY_DIR}/qthelp/xca.qhcp"
	COMMENT "Create context sensitive help index"
  )
  add_custom_command(
	OUTPUT sphinx/rst/database_schema.sql
	COMMAND ${CMAKE_COMMAND} -E make_directory sphinx/rst/_static
	COMMAND ${CMAKE_COMMAND}
		-D "SRC=${PROJECT_SOURCE_DIR}/widgets/database_schema.cpp"
		-D "DST=sphinx/rst/database_schema.sql"
		-P "${PROJECT_SOURCE_DIR}/cmake/database_schema.cmake"
	DEPENDS widgets/database_schema.cpp
	COMMENT "Generating database schema SQL documentation"
  )
  add_custom_command(
	OUTPUT sphinx/rst/COPYRIGHT sphinx/rst/changelog
                sphinx/rst/_static/bigcert.png sphinx/rst
	COMMAND ${CMAKE_COMMAND} -E make_directory sphinx/rst/_static
	COMMAND ${CMAKE_COMMAND} -E copy_directory
				"${PROJECT_SOURCE_DIR}/doc/rst" sphinx/rst
	COMMAND ${CMAKE_COMMAND} -E copy_if_different
				"${PROJECT_SOURCE_DIR}/COPYRIGHT"
				"${PROJECT_SOURCE_DIR}/changelog"
				sphinx/rst
	DEPENDS COPYRIGHT changelog doc/rst
	COMMENT "Prepare Sphinx source directory"
  )
  add_custom_command(
	OUTPUT sphinx/rst/arguments.rst
	COMMAND xcadoc rst sphinx/rst/arguments.rst
  )
  add_custom_target(sphinx-html DEPENDS html/index.html)
  add_custom_target(sphinx-qthelp ALL DEPENDS qthelp/xca.qhc)
  add_custom_target(sphinx DEPENDS sphinx-html sphinx-qthelp)
  add_custom_target(sphinx-src
	DEPENDS sphinx/rst/COPYRIGHT sphinx/rst/changelog
		sphinx/rst/_static/bigcert.png sphinx/rst
		sphinx/rst/database_schema.sql
  )
else()
  add_custom_target(sphinx-qthelp)
endif()

if (NOT WIN32)
  add_custom_command(
	OUTPUT xca.1.gz
	COMMAND sh -c 'cd ${PROJECT_SOURCE_DIR}/doc && cat xca.1.head "${PROJECT_BINARY_DIR}/xca.1.options" xca.1.tail | gzip > ${PROJECT_BINARY_DIR}/xca.1.gz'
	DEPENDS doc/xca.1.head ${PROJECT_BINARY_DIR}/xca.1.options doc/xca.1.tail
  )
  add_custom_command(
	OUTPUT xca.1.options
	COMMAND xcadoc man xca.1.options
  )
  add_custom_target(manpage ALL DEPENDS xca.1.gz)
endif()
