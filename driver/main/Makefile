LEVEL=../../../
include $(LEVEL)/Makefile.config
CXXFLAGS = -fno-rtti
TOOLNAME := clambc-compiler
TOOL_NO_EXPORTS = 1
LINK_COMPONENTS := ClamBC system support bitreader bitwriter ipo
USEDLIBS := clamdriver.a re2c.a clangFrontend.a clangDriver.a clangCodeGen.a\
            clangSema.a clangChecker.a clangAnalysis.a clangRewrite.a\
            clangAST.a clangParse.a clangLex.a clangBasic.a

include $(LEVEL)/Makefile.common
