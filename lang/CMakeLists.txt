
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
