LEVEL=../../
DIRS := clamdriver main

include $(LEVEL)/Makefile.common

PDF := $(PROJ_SRC_DIR)/../docs/user/clambc-user.pdf
docsdir := $(DESTDIR)$(PROJ_prefix)/docs/clamav

install-local:: install-pdf
install-pdf:
	$(Echo) Installing PDF documentation
	$(Verb) $(MKDIR) $(docsdir)
	$(Verb) $(DataInstall) $(PDF) $(docsdir)

