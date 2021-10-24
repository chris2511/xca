
set(S "${PROJECT_SOURCE_DIR}/lang")
set(D "${PROJECT_BINARY_DIR}/lang")
file(MAKE_DIRECTORY "${D}")

set(TS_FILES
${S}/xca_fr.ts	${S}/xca_ja.ts	${S}/xca_tr.ts	${S}/xca.ts
${S}/xca_de.ts	${S}/xca_hr.ts	${S}/xca_nl.ts	${S}/xca_ru.ts
${S}/xca_es.ts	${S}/xca_it.ts	${S}/xca_pl.ts	${S}/xca_sk.ts
${S}/xca_zh_CN.ts	${S}/xca_pt_BR.ts	${S}/xca_id.ts
)

qt5_add_translation(QM_FILES ${TS_FILES})
list(APPEND APP_RESOURCES ${QM_FILES})

add_custom_target(translations DEPENDS ${QM_FILES})
add_dependencies(${CMAKE_PROJECT_NAME} translations)
target_sources(${CMAKE_PROJECT_NAME} PRIVATE ${QM_FILES})

if (UNIX AND NOT APPLE)
  install(FILES ${QM_FILES}
	DESTINATION ${CMAKE_INSTALL_DATADIR}/${CMAKE_PROJECT_NAME}/i18n
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
