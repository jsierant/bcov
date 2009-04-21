AC_INIT(bcov,0.2)
AC_CONFIG_SRCDIR(src/coverage.cpp)
AM_INIT_AUTOMAKE
AC_PROG_CXX
AC_PROG_INSTALL
AC_LANG_CPLUSPLUS

AC_CHECK_LIB([elf], [elf_end],
	,
	[AC_MSG_FAILURE([libelf is required for bcov])]
)


AC_ARG_WITH(libdwarf,
	[AS_HELP_STRING([--with-libdwarf], [specify the libdwarf directory])],
	[
		if test X${withval} = X; then :; else
			LIBDWARF_DIR=${withval}
			LIBDWARF_DIR=`cd ${LIBDWARF_DIR} 2> /dev/null && pwd || echo ${LIBDWARF_DIR}`
			LDFLAGS="${LDFLAGS} -L${LIBDWARF_DIR}"
			CPPFLAGS="${CPPFLAGS} -I${LIBDWARF_DIR}"
			AC_MSG_CHECKING(libdwarf directory)
			AC_MSG_RESULT([${LIBDWARF_DIR}])
		fi
	]
	)

AC_CHECK_LIB([dwarf], [dwarf_init],
	,
	[AC_MSG_FAILURE([libdwarf is required for bcov])]
)

AC_CHECK_HEADERS([libdwarf.h], [],
	[AC_MSG_FAILURE([libdwarf.h is required for bcov])]
)

AC_CONFIG_FILES([Makefile
	src/Makefile])
AC_OUTPUT

