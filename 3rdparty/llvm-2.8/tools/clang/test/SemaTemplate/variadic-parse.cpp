// RUN: %clang_cc1 -fsyntax-only -verify %s -std=c++0x

// Parsing type parameter packs.
template <typename ... Args> struct T1 {};
template <typename ... > struct T2 {};

