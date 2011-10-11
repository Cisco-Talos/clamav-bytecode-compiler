LEVEL=../../
DIRS := clamdriver main

include $(LEVEL)/Makefile.common

PDF1 := $(PROJ_SRC_DIR)/../docs/user/clambc-user.pdf
PDF2 := $(PROJ_SRC_DIR)/../docs/doxygen/latex/refman.pdf
HTMLD := $(PROJ_SRC_DIR)/../docs/doxygen/html
docsdir := $(DESTDIR)$(PROJ_prefix)/docs/clamav

install-local:: install-pdf install-html
install-pdf:
	$(Echo) Installing PDF documentation
	$(Verb) $(MKDIR) $(docsdir)
	$(Verb) $(DataInstall) $(PDF1) $(docsdir)
	$(Verb) $(DataInstall) $(PDF2) $(docsdir)
install-html:
	$(Echo) Installing HTML API documentation
	$(Verb) $(MKDIR) $(docsdir)
	$(Verb) $(CP) -r $(HTMLD) $(docsdir)

