
set(S "${PROJECT_SOURCE_DIR}/lang")
set(D "${PROJECT_BINARY_DIR}")

# English (en) must be first for Info.plist
list(APPEND XCA_LANGUAGES en bg de es fa fr hr id it ja ko nl pl pt_BR ru sk tr zh_CN)
list(JOIN XCA_LANGUAGES "</string>\n		<string>" LANGUAGES_PLIST)

foreach(lang ${XCA_LANGUAGES})
  guid(${lang})
  list(APPEND TS_FILES ${S}/xca_${lang}.ts)
  list(APPEND LANG_COMPREFS "  <ComponentRef Id=\"Ci18n.${lang}\"/>\n")
  set(LANG_COMPS "  <Component Id=\"Ci18n.${lang}\" Guid=\"${GUID}\">
    <File Id=\"xca_${lang}.qm\" Source=\"${D}/xca_${lang}.qm\" KeyPath=\"yes\"/>\n")
  if(EXISTS ${_qt_bin_dir}/../translations/qtbase_${lang}.qm)
    list(APPEND QT_QM_FILES ${_qt_bin_dir}/../translations/qtbase_${lang}.qm)
    string(APPEND LANG_COMPS "    <File Id=\"qtbase_${lang}.qm\" Source=\"${_qt_bin_dir}/../translations/qtbase_${lang}.qm\"/>\n")
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
  if (${QT_VERSION} VERSION_LESS 5.12.0)
    qt5_add_translation(QM_FILES ${TS_FILES})
  else()
    qt5_add_translation(QM_FILES ${TS_FILES} OPTIONS -silent)
  endif()
  message(STATUS "Updating translations from source with 'lupdate' only supported with QT6")
  target_sources(${CMAKE_PROJECT_NAME} PRIVATE ${QM_FILES})
else()
  get_target_property(LIBSRC xcalib SOURCES)
  get_target_property(XCASRC xca SOURCES)
  qt_add_translations(xca TS_FILES ${TS_FILES} ${S}/xca.ts
                          LRELEASE_OPTIONS -silent
                          QM_FILES_OUTPUT_VARIABLE QM_FILES
                          PLURALS_TS_FILE ${S}/xca_en.ts
                          SOURCES ${LIBSRC} ${XCASRC}
  )
  if (${QT_VERSION} VERSION_LESS 6.7.0)
    message(STATUS "At least QT 6.7.0 required for PLURALS_TS_FILE")
    add_custom_target(trans COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --cyan
        "At least QT 6.7.0 required for PLURALS_TS_FILE. It will explode the xca_en.ts"
        COMMENT "Target 'trans' does not work with QT ${QT_VERSION}"
    )
  else()
    add_custom_target(trans DEPENDS xca_lupdate "${D}/xca.pot")
  endif()
endif()
list(APPEND APP_RESOURCES ${QM_FILES} ${QT_QM_FILES})
target_sources(${CMAKE_PROJECT_NAME} PRIVATE ${QM_FILES} ${QT_QM_FILES})

if (UNIX AND NOT APPLE)
  install(FILES ${QM_FILES}
          DESTINATION ${CMAKE_INSTALL_DATADIR}/${CMAKE_PROJECT_NAME}/i18n
  )
elseif(WIN32)
  install(FILES ${QM_FILES} ${QT_QM_FILES}
          DESTINATION ${RUNTIME_DEST}/i18n
  )
endif()

find_program(LCONVERT lconvert HINTS ${_qt_bin_dir})
if (LCONVERT)
  add_custom_command(
    OUTPUT "${D}/xca.pot"
    COMMAND ${LCONVERT} -if ts -of po -i "${S}/xca.ts" -o "${D}/xca.pot"
    COMMAND ${CMAKE_COMMAND} -E copy "${D}/xca.pot" "${S}/xca.pot"
    DEPENDS "${S}/xca.ts"
    COMMENT "Update POT file"
  )
endif()
