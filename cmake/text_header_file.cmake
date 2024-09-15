
if (FILE AND SRC AND DST)
  if (APPLE)
    set(DIR_HINT "HOME/Library/Application Support/data/xca/${FILE}.txt")
  elseif (WIN32)
    set(DIR_HINT "PROFILE\\Application Data\\xca\\${FILE}.txt")
  else()
    set(DIR_HINT "/usr/local/share/xca/${FILE}.txt or HOME/.local/share/xca/${FILE}.txt")
  endif()

  file(READ "${SRC}/preamble.txt" PREAMBLE)
  file(READ "${SRC}/${FILE}.text" CONT)
  file(WRITE "${DST}/${FILE}.txt"
       ${PREAMBLE} "\n# "
       ${DIR_HINT} "\n"
       ${CONT})
else()
  message(FATAL_ERROR "Mandatory FILE or SRC variable not defined")
endif()
