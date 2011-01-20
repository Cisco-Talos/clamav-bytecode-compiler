# OASIS_START
# DO NOT EDIT (digest: bc1e05bfc8b39b664f29dae8dbd3ebbb)

SETUP = ocaml setup.ml

build: setup.data
	$(SETUP) -build $(BUILDFLAGS)

doc: setup.data build
	$(SETUP) -doc $(DOCFLAGS)

test: setup.data build
	$(SETUP) -test $(TESTFLAGS)

all: 
	$(SETUP) -all $(ALLFLAGS)

install: setup.data
	$(SETUP) -install $(INSTALLFLAGS)

uninstall: setup.data
	$(SETUP) -uninstall $(UNINSTALLFLAGS)

reinstall: setup.data
	$(SETUP) -reinstall $(REINSTALLFLAGS)

clean: 
	$(SETUP) -clean $(CLEANFLAGS)

distclean: 
	$(SETUP) -distclean $(DISTCLEANFLAGS)

setup.data:
	$(SETUP) -configure $(CONFIGUREFLAGS)

.PHONY: build doc test all install uninstall reinstall clean distclean configure

# OASIS_STOP
# otags rule
ALLML := $(wildcard src/*.ml src/*.mli)
tags: $(ALLML)
	otags -pc -pa r $(ALLML) -pr $(wildcard 3rdparty/llvm-2.8/bindings/ocaml/**/*.mli)  -vi

# make check rule alias
check: test
	$(MAKE) -C obj check-all

SETUP = export OCAMLPATH=`pwd`/obj/Release+Asserts/lib/ocaml; ocaml setup.ml

headache:
	git ls-files -- src/ tests/ | xargs headache -h _header
