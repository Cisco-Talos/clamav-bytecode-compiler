#
# Find the ClamAV programs and headers needed for the test suite.
#
# If found, will set:
#   ClamAV_FOUND, ClamAV_VERSION, and
#       - clamscan_EXECUTABLE
#       - clambc_EXECUTABLE
#       - sigtool_EXECUTABLE
#       - clambc_headers_DIRECTORY
#
# If you have a custom install location for ClamAV, you can provide a hint
# by settings -DClamAV_HOME=<clamav install prefix>
#

find_program(clamscan_EXECUTABLE
    NAMES clamscan clamscan.exe
    HINTS "${ClamAV_HOME}"
    PATH_SUFFIXES "bin"
)
if(NOT clamscan_EXECUTABLE AND NOT ClamAV_FIND_QUIETLY)
    message("Unable to find clamscan")
endif()

find_program(clambc_EXECUTABLE
    NAMES clambc clambc.exe
    HINTS "${ClamAV_HOME}"
    PATH_SUFFIXES "bin"
)
if(NOT clambc_EXECUTABLE AND NOT ClamAV_FIND_QUIETLY)
    message("Unable to find clambc")
endif()

find_program(sigtool_EXECUTABLE
    NAMES sigtool sigtool.exe
    HINTS "${ClamAV_HOME}"
    PATH_SUFFIXES "bin"
)
if(NOT sigtool_EXECUTABLE AND NOT ClamAV_FIND_QUIETLY)
    message("Unable to find sigtool")
endif()

if(clamscan_EXECUTABLE AND clambc_EXECUTABLE AND sigtool_EXECUTABLE)
    execute_process(COMMAND "${clamscan_EXECUTABLE}" --version
        OUTPUT_VARIABLE ClamAV_VERSION_OUTPUT
        ERROR_VARIABLE  ClamAV_VERSION_ERROR
        RESULT_VARIABLE ClamAV_VERSION_RESULT
    )
    if(NOT ${ClamAV_VERSION_RESULT} EQUAL 0)
        if(NOT ClamAV_FIND_QUIETLY)
            message(STATUS "ClamAV not found: Failed to determine version.")
        endif()
        unset(clamscan_EXECUTABLE)
    else()
        string(REGEX
            MATCH "[0-9]+\\.[0-9]+(\\.[0-9]+)?(-devel)?"
            ClamAV_VERSION "${ClamAV_VERSION_OUTPUT}"
        )
        set(ClamAV_VERSION "${ClamAV_VERSION}")
        set(ClamAV_FOUND 1)

        # Look for the clambc-headers. E.g.: <clamav prefix>/lib/clambc-headers/0.104.0
        #
        # In the future, the clamav-derived headers for compiling signatures will be
        # installed with clamav, and this path will be necessary to find them for running
        # the test suite.
        find_file(clambc_headers_DIRECTORY
            clambc-headers/${ClamAV_VERSION}
            HINTS "${ClamAV_HOME}"
            PATH_SUFFIXES "lib"
        )

        if(NOT ClamAV_FIND_QUIETLY)
            message(STATUS "ClamAV found: ${ClamAV_VERSION}")
            message(STATUS " clamscan:    ${clamscan_EXECUTABLE}")
            message(STATUS " clambc:      ${clambc_EXECUTABLE}")
            message(STATUS " sigtool:     ${sigtool_EXECUTABLE}")
            message(STATUS " bc headers:  ${clambc_headers_DIRECTORY}")
        endif()

        if(NOT clambc_headers_DIRECTORY)
            set(clambc_headers_DIRECTORY "")
        endif()
    endif()

    mark_as_advanced(clamscan_EXECUTABLE clambc_EXECUTABLE sigtool_EXECUTABLE ClamAV_VERSION)
else()
    if(ClamAV_FIND_REQUIRED)
        message(FATAL_ERROR "ClamAV not found.")
    else()
        if(NOT ClamAV_FIND_QUIETLY)
            message(STATUS "${_msg}")
        endif()
    endif()
endif()
