
set(S "${PROJECT_SOURCE_DIR}/misc")
set(D "${PROJECT_BINARY_DIR}/misc")
file(MAKE_DIRECTORY ${D})

configure_file(${S}/Info.plist.in ${D}/Info.plist)
configure_file(${S}/dynamic.wxs.in ${D}/dynamic.wxs)

set(CPACK_RESOURCE_FILE_LICENSE "${S}/copyright.rtf")
set(CPACK_BUNDLE_PLIST ${D}/Info.plist)
set(CPACK_DMG_DS_STORE ${S}/dmg.DS_Store)

set_property(TARGET ${PROJECT_NAME}
             PROPERTY MACOSX_BUNDLE_INFO_PLIST ${D}/Info.plist)

##### XCA Templates
list(APPEND XCA_TEMPLATES CA.xca TLS_server.xca TLS_client.xca)
list(TRANSFORM XCA_TEMPLATES PREPEND ${S}/)
target_sources(${CMAKE_PROJECT_NAME} PRIVATE ${XCA_TEMPLATES})
list(APPEND APP_RESOURCES "${XCA_TEMPLATES}")

##### Text Files oids.txt eku.txt dn.txt

macro(Text_header file)
  if (APPLE)
    set(DIR_HINT "HOME/Library/Application Support/data/de.hohnstaedt.xca/${file}.txt")
  elseif (WIN32)
    set(DIR_HINT "PROFILE\\Application Data\\xca\\${file}.txt")
  else()
    set(DIR_HINT "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_DATADIR}/${file}.txt or \$HOME/.local/share/de.hohnstaedt.xca/${file}.txt")
  endif()

  file(READ "${S}/preamble.txt" PREAMBLE)
  file(READ "${S}/${file}.text" CONT)
  file(WRITE "${D}/${file}.txt"
       ${PREAMBLE} "\n# "
       ${DIR_HINT} "\n"
       ${CONT}
  )
  list(APPEND TEXT_FILES "${D}/${file}.txt")
endmacro()

Text_header(dn)
Text_header(eku)
Text_header(oids)

foreach(misc_name ${TEXT_FILES} ${XCA_TEMPLATES})
  string(REGEX REPLACE ".*/" "" misc_basename ${misc_name})
  guid(${misc_basename})
  list(APPEND MISC_COMPREFS "  <ComponentRef Id=\"Cmisc.${misc_basename}\"/>\n")
  list(APPEND MISC_COMPS "  <Component Id=\"Cmisc.${misc_basename}\" Guid=\"${GUID}\">
    <File Id=\"misc.${misc_basename}\" Source=\"${misc_name}\" KeyPath=\"yes\"/>
  </Component>\n")
endforeach()

string(APPEND WIX_MISC_CONTENT
"<DirectoryRef Id=\"INSTALLDIR\">\n" ${MISC_COMPS} "</DirectoryRef>
<ComponentGroup Id=\"GroupMisc\">\n" ${MISC_COMPREFS} "</ComponentGroup>")

WixFile(${D}/misc.wxs ${WIX_MISC_CONTENT})

target_sources(${CMAKE_PROJECT_NAME} PRIVATE ${TEXT_FILES})
list(APPEND APP_RESOURCES ${TEXT_FILES})

if (UNIX AND NOT APPLE)
  install(FILES ${TEXT_FILES} ${XCA_TEMPLATES}
        DESTINATION ${CMAKE_INSTALL_DATADIR}/${CMAKE_PROJECT_NAME}
  )
  install(FILES misc/de.hohnstaedt.xca.desktop
        DESTINATION ${CMAKE_INSTALL_DATADIR}/applications
  )
  install(FILES misc/xca.completion
        DESTINATION ${CMAKE_INSTALL_DATADIR}/bash-completion/completions
        RENAME xca
  )
  install(FILES misc/xca.xml
        DESTINATION ${CMAKE_INSTALL_DATADIR}/mime/packages
  )
  install(FILES misc/de.hohnstaedt.xca.metainfo.xml
        DESTINATION ${CMAKE_INSTALL_DATADIR}/metainfo
  )
elseif(WIN32)
  install(FILES ${TEXT_FILES} ${XCA_TEMPLATES}
	  DESTINATION ${RUNTIME_DEST}
  )
endif()
