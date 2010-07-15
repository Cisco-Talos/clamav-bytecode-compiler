AC_INIT(clambc-regex-compile, 0.1)

AC_PROG_OCAML
if test "$OCAMLC" = "no"; then
    AC_MSG_ERROR([You must install the OCaml compiler:
Install the 'ocaml-best-compilers' or 'ocaml' package])
fi

OCAML_MINVERSION="3.11.0"
AS_VERSION_COMPARE(["$OCAMLVERSION"],["$OCAML_MINVERSION"],
   [AC_MSG_ERROR([OCaml version must be at least version "$OCAML_MINVERSION"])])

if test "$OCAMLBUILD" = "no"; then
    AC_MSG_ERROR([You must install ocamlbuild:
Install the 'ocaml-nox' or 'ocaml' package])
fi

AC_PROG_FINDLIB
if test "$OCAMLFIND" = "no"; then
  AC_MSG_ERROR([You must install Ocaml findlib (the ocamlfind command)])
fi

AC_CHECK_OCAML_PKG([extlib])
if test "$OCAML_PKG_extlib" = "no"; then
  AC_MSG_ERROR([Please install OCaml findlib module 'extlib':
Install the 'libextlib-ocaml-dev' or 'ocaml-extlib' package])
fi

if test "$OCAMLBEST" = "opt"; then
  AC_SUBST([OCAMLBEST], [native])
else
  AC_SUBST([OCAMLBEST], [byte])
fi

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
