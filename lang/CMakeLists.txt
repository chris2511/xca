
set(TS_FILES
xca_fr.ts	xca_ja.ts	xca_pt_BR.ts	xca_tr.ts
xca_de.ts	xca_hr.ts	xca_nl.ts	xca_ru.ts
xca_es.ts	xca_it.ts	xca_pl.ts	xca_sk.ts
xca_zh_CN.ts
)
qt5_add_translation(QM_FILES ${TS_FILES})
list(APPEND APP_RESOURCES ${QM_FILES})
set(APP_RESOURCES ${APP_RESOURCES} PARENT_SCOPE)

add_custom_target(translations DEPENDS ${QM_FILES})
add_dependencies(${CMAKE_PROJECT_NAME} translations)

if (UNIX)
  install(FILES ${QM_FILES}
	DESTINATION ${CMAKE_INSTALL_DATADIR}/${CMAKE_PROJECT_NAME}/i18n
  )
endif()

macro(PO_language lang)
  add_custom_command(
	OUTPUT "${CMAKE_CURRENT_SOURCE_DIR}/xca_${lang}X.ts"
	COMMAND ${LCONVERT} -if po -of ts
		-i "${CMAKE_CURRENT_SOURCE_DIR}/${lang}.po"
		-o "${CMAKE_CURRENT_SOURCE_DIR}/xca_${lang}X.ts"
	DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/${lang}.po"
  )
  list(APPEND POTS "${CMAKE_CURRENT_SOURCE_DIR}/xca_${lang}.ts")
endmacro()

find_program(LCONVERT lconvert)

if (LCONVERT)
  add_custom_command(
	OUTPUT "${CMAKE_CURRENT_SOURCE_DIR}/xca.pot"
	COMMAND ${LCONVERT} -if ts -of po
		-i "${CMAKE_CURRENT_SOURCE_DIR}/xca.ts"
		-o "${CMAKE_CURRENT_SOURCE_DIR}/xca.pot"
	DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/xca.ts"
	COMMENT "Update POT file"
  )
  qt5_create_translation(CQM_FILES ${CMAKE_SOURCE_DIR} ${TS_FILES})
  PO_language(tr)
  PO_language(fr)
  PO_language(sk)
endif()

add_custom_target(trans DEPENDS ${CQM_FILES}
		"${CMAKE_CURRENT_SOURCE_DIR}/xca.pot"
)
add_custom_target(po2ts DEPENDS ${POTS})
