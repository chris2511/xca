
set(S "${PROJECT_SOURCE_DIR}/img")
set(D "${PROJECT_BINARY_DIR}/img")
file(MAKE_DIRECTORY ${D})

macro(Install_PNG size)
  install(FILES ${S}/xca-icons.iconset/icon_${size}.png
	DESTINATION ${ICONDIR}/${size}/apps RENAME de.hohnstaedt.xca.png
  )
  install(FILES ${S}/xca-icons.iconset/icon_${size}.png
	DESTINATION ${ICONDIR}/${size}/mimetypes RENAME x-xca-database.png
  )
  install(FILES ${S}/xca-icons.iconset/icon_${size}.png
	DESTINATION ${ICONDIR}/${size}/mimetypes RENAME x-xca-template.png
  )
endmacro()

if(APPLE)

  ###### MAC ICONS
  find_program(ICONUTIL iconutil)
  if(ICONUTIL)
    set(ICONS "${D}/xca-icons.icns")
    file(GLOB ICON_SRC ${S}/xca-icons.iconset/*.png)
    add_custom_command(OUTPUT ${ICONS}
	  COMMAND iconutil --convert icns -o ${ICONS}
		  ${S}/xca-icons.iconset
	  DEPENDS ${ICON_SRC}
    )
    set_source_files_properties(${ICONS} PROPERTIES GENERATED TRUE)
    add_custom_target(mac-icons DEPENDS ${ICONS})
    add_dependencies(${CMAKE_PROJECT_NAME} mac-icons)
    target_sources(${CMAKE_PROJECT_NAME} PRIVATE ${ICONS})
    list(APPEND APP_RESOURCES ${ICONS})
  endif()
  set(CPACK_BUNDLE_ICON ${ICONS})

elseif(WIN32)
    ENABLE_LANGUAGE(RC)
    target_sources(${CMAKE_PROJECT_NAME} PRIVATE ${S}/w32res.rc)
endif()

if (UNIX AND NOT APPLE)

  install(FILES ${S}/xca-32x32.xpm
	DESTINATION ${CMAKE_INSTALL_DATADIR}/pixmaps
  )
  set(ICONDIR ${CMAKE_INSTALL_DATADIR}/icons/hicolor)

  Install_PNG(16x16)
  Install_PNG(32x32)
  Install_PNG(48x48)
  Install_PNG(64x64)

endif()
