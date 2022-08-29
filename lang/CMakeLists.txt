
set(S "${PROJECT_SOURCE_DIR}/lang")
set(D "${PROJECT_BINARY_DIR}")

list(APPEND XCA_LANGUAGES id hr nl pt_BR zh_CN fa)
list(APPEND XCAQM_LANGUAGES de fr ja pl ru tr es it sk)

foreach(lang ${XCA_LANGUAGES} ${XCAQM_LANGUAGES})
  list(APPEND TS_FILES ${S}/xca_${lang}.ts)
endforeach()

foreach(lang ${XCA_LANGUAGES} ${XCAQM_LANGUAGES})
  guid(${lang})
  list(APPEND LANG_COMPREFS "  <ComponentRef Id=\"Ci18n.${lang}\"/>\n")
  set(LANG_COMPS "  <Component Id=\"Ci18n.${lang}\" Guid=\"${GUID}\">
    <File Id=\"xca_${lang}.qm\" Source=\"${D}/xca_${lang}.qm\" KeyPath=\"yes\"/>\n")
  if(${lang} IN_LIST XCAQM_LANGUAGES)
    string(APPEND LANG_COMPS "    <File Id=\"qt_${lang}.qm\" Source=\"${D}/translations/qt_${lang}.qm\"/>\n")
  endif()
  string(APPEND LANG_COMPS "  </Component>\n")
  list(APPEND LANG_ALLCOMPS ${LANG_COMPS})
endforeach()

string(APPEND WIX_LANG_CONTENT
  "<DirectoryRef Id=\"i18n\">\n" ${LANG_ALLCOMPS} "</DirectoryRef>\n"
  "<ComponentGroup Id=\"GroupI18n\">\n" ${LANG_COMPREFS} "</ComponentGroup>"
)

WixFile(${D}/language.wxs ${WIX_LANG_CONTENT})

if (${QT_VERSION} VERSION_LESS 6.0.0)
  qt5_add_translation(QM_FILES ${TS_FILES} OPTIONS -silent)
else()
  qt_add_translation(QM_FILES ${TS_FILES} OPTIONS -silent)
endif()
list(APPEND APP_RESOURCES ${QM_FILES})

add_custom_target(translations DEPENDS ${QM_FILES})
add_dependencies(${CMAKE_PROJECT_NAME} translations)
target_sources(${CMAKE_PROJECT_NAME} PRIVATE ${QM_FILES})

if (UNIX AND NOT APPLE)
  install(FILES ${QM_FILES}
	DESTINATION ${CMAKE_INSTALL_DATADIR}/${CMAKE_PROJECT_NAME}/i18n
  )
elseif(WIN32)
  install(FILES ${QM_FILES}
	  DESTINATION ${RUNTIME_DEST}/i18n
  )
endif()

find_program(LCONVERT lconvert)

# cmake -DTRANS=1 ../xca && make trans
if (LCONVERT AND TRANS)
  add_custom_command(
	OUTPUT "${S}/xca.pot"
	COMMAND ${LCONVERT} -if ts -of po -i "${S}/xca.ts" -o "${S}/xca.pot"
	DEPENDS "${S}/xca.ts"
	COMMENT "Update POT file"
  )
  qt5_create_translation(CQM_FILES ${CMAKE_SOURCE_DIR} ${TS_FILES})

  add_custom_target(trans DEPENDS ${CQM_FILES} "${S}/xca.pot")
endif()
