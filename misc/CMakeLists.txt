
set(S "${PROJECT_SOURCE_DIR}/misc")
set(D "${PROJECT_BINARY_DIR}/misc")
file(MAKE_DIRECTORY ${D})

configure_file(${S}/Info.plist.in ${D}/Info.plist)

set(CPACK_RESOURCE_FILE_LICENSE "${S}/copyright.rtf")
set(CPACK_BUNDLE_PLIST "${D}/Info.plist")
set_property(TARGET ${PROJECT_NAME}
	     PROPERTY MACOSX_BUNDLE_INFO_PLIST "${D}/Info.plist")

##### XCA Templates

foreach(templ CA.xca TLS_server.xca TLS_client.xca)
  list(APPEND XCA_TEMPLATES ${S}/${templ})
endforeach()
target_sources(${CMAKE_PROJECT_NAME} PRIVATE ${XCA_TEMPLATES})
list(APPEND APP_RESOURCES "${XCA_TEMPLATES}")

##### Text Files ids.txt eku.txt dn.txt

macro(Text_header file)
  add_custom_command(OUTPUT "${D}/${file}.txt"
        COMMAND ${CMAKE_COMMAND} -DFILE=${file}
		-DSRC="${S}" -DDST="${D}"
                -P "${PROJECT_SOURCE_DIR}/cmake/text_header_file.cmake"
        DEPENDS "${S}/${file}.text" "${S}/preamble.txt"
  )
  list(APPEND TEXT_FILES "${D}/${file}.txt")
endmacro()

Text_header(dn)
Text_header(eku)
Text_header(oids)

target_sources(${CMAKE_PROJECT_NAME} PRIVATE ${TEXT_FILES})
list(APPEND APP_RESOURCES ${TEXT_FILES})

if (UNIX AND NOT APPLE)
  install(FILES ${TEXT_FILES} ${XCA_TEMPLATES}
        DESTINATION ${CMAKE_INSTALL_DATADIR}/${CMAKE_PROJECT_NAME}
  )
  install(FILES misc/xca.desktop
        DESTINATION ${CMAKE_INSTALL_DATADIR}/applications
  )
  install(FILES misc/xca.completion
        DESTINATION ${CMAKE_INSTALL_DATADIR}/bash-completion/completions/xca
  )
  install(FILES misc/xca.xml
	DESTINATION ${CMAKE_INSTALL_DATADIR}/mime/packages
  )
endif()
