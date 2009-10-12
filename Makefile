LEVEL = ../..
DIRS := include lib tools docs

include $(LEVEL)/Makefile.common

ifneq ($(PROJ_SRC_ROOT),$(PROJ_OBJ_ROOT))
all::
	$(Verb) if [ ! -f test/Makefile ]; then \
	  $(MKDIR) test; \
	  $(CP) $(PROJ_SRC_DIR)/test/Makefile test/Makefile; \
	fi
endif

test::
	@ $(MAKE) -C test 

report::
	@ $(MAKE) -C test report

clean::
	@ $(MAKE) -C test clean

tags::
	$(Verb) etags `find . -type f -name \*.h | grep -v /lib/Headers | grep -v /test/` `find . -type f -name \*.cpp | grep -v /lib/Headers | grep -v /test/`

cscope.files:
	find tools lib include -name '*.cpp' \
	                    -or -name '*.def' \
	                    -or -name '*.td' \
	                    -or -name '*.h' > cscope.files

.PHONY: test report clean cscope.files

install-local::
	$(Echo) Installing include files
	$(Verb) $(MKDIR) $(PROJ_includedir)
	$(Verb) if test -d "$(PROJ_SRC_ROOT)/tools/clang/include" ; then \
	  cd $(PROJ_SRC_ROOT)/tools/clang/include && \
	  for  hdr in `find . -type f '!' '(' -name '*~' \
	      -o -name '.#*' -o -name '*.in' -o -name '*.txt' \
	      -o -name 'Makefile' -o -name '*.td' ')' -print \
              | grep -v CVS | grep -v .svn` ; do \
	    instdir=`dirname "$(PROJ_includedir)/$$hdr"` ; \
	    if test \! -d "$$instdir" ; then \
	      $(EchoCmd) Making install directory $$instdir ; \
	      $(MKDIR) $$instdir ;\
	    fi ; \
	    $(DataInstall) $$hdr $(PROJ_includedir)/$$hdr ; \
	  done ; \
	fi
ifneq ($(PROJ_SRC_ROOT),$(PROJ_OBJ_ROOT))
	$(Verb) if test -d "$(PROJ_OBJ_ROOT)/tools/clang/include" ; then \
	  cd $(PROJ_OBJ_ROOT)/tools/clang/include && \
	  for hdr in `find . -type f '!' '(' -name 'Makefile' ')' -print \
            | grep -v CVS | grep -v .tmp` ; do \
	    $(DataInstall) $$hdr $(PROJ_includedir)/$$hdr ; \
	  done ; \
	fi
endif
