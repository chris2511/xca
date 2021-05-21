
##### XCA Templates

foreach(templ CA.xca TLS_server.xca TLS_client.xca)
  list(APPEND XCA_TEMPLATES ${CMAKE_CURRENT_SOURCE_DIR}/${templ})
endforeach()
target_sources(${CMAKE_PROJECT_NAME} PRIVATE ${XCA_TEMPLATES})
list(APPEND APP_RESOURCES "${XCA_TEMPLATES}")

##### Text Files ids.txt eku.txt dn.txt

macro(Text_header file)
  add_custom_command(OUTPUT ${file}.txt
        COMMAND ${CMAKE_COMMAND} -DFILE=${file}
		-DSRC="${CMAKE_CURRENT_SOURCE_DIR}"
                -P "${PROJECT_SOURCE_DIR}/cmake/text_header_file.cmake"
        DEPENDS ${file}.text
  )
  list(APPEND TEXT_FILES "${CMAKE_CURRENT_BINARY_DIR}/${file}.txt")
  list(APPEND SRC_TEXT_FILES "${CMAKE_CURRENT_SOURCE_DIR}/${file}.text")
endmacro()

Text_header(dn)
Text_header(eku)
Text_header(oids)

add_custom_target(text_files ALL DEPENDS ${TEXT_FILES})
target_sources(${CMAKE_PROJECT_NAME} PRIVATE ${SRC_TEXT_FILES})

list(APPEND APP_RESOURCES ${TEXT_FILES})

if (UNIX)
  install(FILES ${TEXT_FILES} ${XCA_TEMPLATES}
        DESTINATION ${CMAKE_INSTALL_DATADIR}/${CMAKE_PROJECT_NAME}
  )
  install(FILES xca.desktop
        DESTINATION ${CMAKE_INSTALL_DATADIR}/applications
  )
  install(FILES xca.completion
        DESTINATION ${CMAKE_INSTALL_DATADIR}/bash-completion/completions/xca
  )
  install(FILES xca.xml DESTINATION ${CMAKE_INSTALL_DATADIR}/mime/packages)
endif()

set(APP_RESOURCES ${APP_RESOURCES} PARENT_SCOPE)
