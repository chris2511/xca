
list(APPEND srcs PwDialogMock.h importPEM.cpp main.cpp main.h
	newKey.cpp pem.cpp export.cpp renewal.cpp)

list(TRANSFORM srcs PREPEND ${PROJECT_SOURCE_DIR}/test/)

add_executable(testxca img/imgres.qrc ${srcs}
		${UI_FILES} ${PROJECT_BINARY_DIR}/local.h)

add_test(NAME testxca COMMAND testxca)
set_tests_properties(testxca PROPERTIES LABELS gui)
add_dependencies(tests testxca)
target_link_libraries(testxca ${ASAN_LIB} ${QT}::Test xcalib)

if (APPLE)
  target_link_libraries(testxca
	${IOKIT_LIBRARY} ${COREFOUNDATION_LIBRARY}
  )
endif()
