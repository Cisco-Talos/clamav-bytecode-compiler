rm -f re2internal.mli
ocamlc -c re2internal.ml &&
ocamlc -i re2internal.ml > re2internal.mli &&
ocamlc -c re2internal.mli &&
make re2/obj/libre2.a -j4 &&
g++ -Ire2 re2internal_stubs.cc -c &&
ocamlc -g -verbose -a -custom -o re2internal.cma re2internal.mli re2internal.ml re2internal_stubs.o -cclib -Lre2/obj -cclib -lre2 -cclib -lstdc++
ocamlc -g re2internal.cma test.ml -o foo &&
ocamlopt -g -verbose -a -o re2internal.cmxa re2internal.mli re2internal.ml re2internal_stubs.o -cclib -Lre2/obj -cclib -lre2 -cclib -lstdc++ -cclib -pthread &&
ocamlopt -g re2internal.cmxa test.ml -o foo2
ocamlmktop re2internal.cma -o footop
ocamlc -custom -g re2internal.cma compile.ml -o foo
