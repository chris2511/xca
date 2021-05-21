
macro(Install_PNG size)
  install(FILES xca-icons.iconset/icon_${size}.png
	DESTINATION ${ICONDIR}/${size}/apps RENAME xca.png
  )
  install(FILES xca-icons.iconset/icon_${size}.png
	DESTINATION ${ICONDIR}/${size}/mimetypes RENAME x-xca-database.png
  )
  install(FILES xca-icons.iconset/icon_${size}.png
	DESTINATION ${ICONDIR}/${size}/mimetypes RENAME x-xca-template.png
  )
endmacro()

if(APPLE)
  ###### MAC ICONS
  find_program(ICONUTIL iconutil)
  if(ICONUTIL)
    set(ICONS "${CMAKE_CURRENT_BINARY_DIR}/xca-icons.icns")
    file(GLOB ICON_SRC ${CMAKE_CURRENT_SOURCE_DIR}/xca-icons.iconset/*.png)
    add_custom_command(OUTPUT ${ICONS}
	  COMMAND iconutil --convert icns -o ${ICONS}
		  ${CMAKE_CURRENT_SOURCE_DIR}/xca-icons.iconset
	  DEPENDS ${ICON_SRC}
    )
    add_custom_target(mac-icons DEPENDS ${ICONS})
    list(APPEND APP_RESOURCES ${ICONS})
    target_sources(${CMAKE_PROJECT_NAME} PRIVATE ${ICON_SRC})
    add_dependencies(${CMAKE_PROJECT_NAME} mac-icons)
  endif()
endif()

if (UNIX)

  install(FILES xca-32x32.xpm
        DESTINATION ${CMAKE_INSTALL_DATADIR}/pixmaps
  )
  set(ICONDIR ${CMAKE_INSTALL_DATADIR}/icons/hicolor)

  Install_PNG(16x16)
  Install_PNG(32x32)
  Install_PNG(48x48)
  Install_PNG(64x64)
endif()
