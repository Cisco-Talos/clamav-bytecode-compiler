#!/bin/bash

opt-16 -load-pass-plugin examples/NewPassManager/AnalysisPlugin/libanalysisplugin.so -passes=example-pass-with-analysis analysis_test.ll -o analysis_test.t.ll

