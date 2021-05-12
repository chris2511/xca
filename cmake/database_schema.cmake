
if (SRC AND DST)
  file(READ ${SRC} DB_SCHEMA)
  string(REPLACE "<<" "" DB_SCHEMA "${DB_SCHEMA}")
  string(REPLACE "\\\"" "'" DB_SCHEMA "${DB_SCHEMA}")
  string(REPLACE "//" "--" DB_SCHEMA "${DB_SCHEMA}")
  string(REPLACE "\"" " " DB_SCHEMA "${DB_SCHEMA}")
  string(REGEX REPLACE "^[ \t\r\n]+schemas\\[(.*)\\].*"
			"  -- Schema Version \\1" DB_SCHEMA "${DB_SCHEMA}")
  file(WRITE ${DST} "${DB_SCHEMA}")
else()
  message(FATAL_ERROR "Mandatory FILE or SRC variable not defined")
endif()
