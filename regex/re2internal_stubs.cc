// Copyright (c) 2010 Sourcefire, Inc. All rights reserved.
// Author: Török Edvin
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//   * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "re2/re2.h"
#include "re2/regexp.h"
#include "re2/prog.h"

extern "C" {
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/custom.h>
#include <caml/fail.h>
}

using namespace re2;

#define Is_list(x)   ((Is_long(x) && !Long_val(x)) || (Is_block(x) && !Tag_val(x)))
#define Is_string(x) (Is_block(x) && Tag_val(x) == String_tag)
#define Is_custom(x) (Is_block(x) && Tag_val(x) == Custom_tag)

// Regexp objects as Caml custom blocks
static char regexp_id[] = "re2.internal.regexp";
static Regexp*& regexp_val(value v) {
    assert(Is_custom(v));
    assert(Custom_ops_val(v)->identifier == regexp_id);
    return *(reinterpret_cast<Regexp**>Data_custom_val(v));
}

static void regexp_finalize(value v)
{
    regexp_val(v)->Decref();
}

static struct custom_operations regexp_ops = {
    regexp_id,
    regexp_finalize,
    custom_compare_default,
    custom_hash_default,
    custom_serialize_default,
    custom_deserialize_default
};

// Prog objects as Caml custom blocks
static char prog_id[] = "re2.internal.prog";
static Prog*& prog_val(value v) {
    assert(Is_custom(v));
    assert(Custom_ops_val(v)->identifier == prog_id);
    return *(reinterpret_cast<Prog**>Data_custom_val(v));
}

static void prog_finalize(value v)
{
    delete prog_val(v);
}

static struct custom_operations prog_ops = {
    prog_id,
    prog_finalize,
    custom_compare_default,
    custom_hash_default,
    custom_serialize_default,
    custom_deserialize_default
};

// DFAState objects as Caml custom blocks
static char state_id[] = "re2.internal.state";
static DFAState *& state_val(value v) {
    assert(Is_custom(v));
    assert(Custom_ops_val(v)->identifier == state_id);
    return *(reinterpret_cast<DFAState **>Data_custom_val(v));
}

static int state_compare(value v1, value v2)
{
    DFAState *s1 = state_val(v1);
    DFAState *s2 = state_val(v2);
    return s1 == s2 ? 0 : s1 < s2 ? -1 : 1;
}

static long state_hash(value v)
{
    DFAState *s1 = state_val(v);
    return (long)s1;
}

static struct custom_operations state_ops = {
    state_id,
    custom_finalize_default,
    state_compare,
    state_hash,
    custom_serialize_default,
    custom_deserialize_default
};

#define TRYCATCH(x) \
  try { x }\
  catch (std::exception& e) {\
    caml_failwith(e.what());\
  }\
  catch (...) {\
    caml_failwith("Unknown C++ exception thrown\n");\
  }

// Caml interface
extern "C" CAMLprim value re2i_parse(value options, value pattern)
{
    CAMLparam2(options, pattern);
    CAMLlocal1(result);

    assert(Is_list(options));
    assert(Is_string(pattern));
    Regexp *re;
    //TODO: convert 'options' to these flags
    TRYCATCH(
    int flags = Regexp::Latin1 | Regexp::LikePerl;
    RegexpStatus status;
    re = Regexp::Parse(String_val(pattern),
			       static_cast<Regexp::ParseFlags>(flags), &status);
    if (!re)
         caml_invalid_argument("Invalid regular expression");
    re = re->Simplify();
    )

    //XXX: use a walker to determine how big the regex is, for now just GC every
    //100 regexps
    result = alloc_custom(&regexp_ops, sizeof(Regexp*), 1, 100);
    regexp_val(result) = re;
    CAMLreturn (result);
}

extern "C" CAMLprim value re2i_compile_regex(value anchored, value forward,
					     value regex)
{
    CAMLparam3(anchored, forward, regex);
    CAMLlocal1(result);
    assert(Is_long(anchored));
    assert(Is_long(forward));
    assert(Is_custom(regex));
    Regexp* re = regexp_val(regex);
    if (!re)
      caml_invalid_argument("Compiled regular expression expected");
    Prog* prog;
    TRYCATCH(
    if (Bool_val(forward)) {
	//XXX: allow setting maxmem
	prog = re->CompileToProg(RE2::Options::kDefaultMaxMem*2/3);
    } else {
	prog = re->CompileToReverseProg(RE2::Options::kDefaultMaxMem/3);
    }
    if (!prog)
       caml_failwith("Unable to compile regex");
//    std::cerr << "prog: " << prog->Dump() << "\n";
    )

    //XXX: use constant for max progs
    result = alloc_custom(&prog_ops, sizeof(Prog*), prog->size(), 10000);
    prog_val(result) = prog;
    CAMLreturn(result);
}

extern "C" CAMLprim value re2i_prog_startstate(value longestmatch, value progval)
{
    CAMLparam2(longestmatch, progval);
    CAMLlocal1(result);
    assert(Is_long(longestmatch) && Is_custom(progval));

    Prog *prog = prog_val(progval);
    if (!prog)
      caml_invalid_argument("Compiled regex program expected");
    DFAState *s;
    TRYCATCH(
    s = prog->GetStartState(Bool_val(longestmatch) ? Prog::kLongestMatch : Prog::kFirstMatch, false);
    )
    //XXX: use some other measure for state size
    result = alloc_custom(&state_ops, sizeof(DFAState*), 1, 10000);
    state_val(result) = s;
    CAMLreturn(result);
}

// Keep this in sync with 'type state_class'
enum {
    Generic = 0,
    Dead,
    FullMatch
};

// Keep in sync with re2/dfa.cc
#define DeadState reinterpret_cast<DFAState*>(1)
#define FullMatchState reinterpret_cast<DFAState*>(2)
extern "C" CAMLprim value re2i_classify_state(value state)
{
    CAMLparam1(state);
    int result;
    assert(Is_custom(state));
    DFAState *s = state_val(state);
    if (!s)
      caml_invalid_argument("Regex DFA state expected");
    if (s == DeadState)
	result = Dead;
    else if (s == FullMatchState)
	result = FullMatch;
    else
	result = Generic;
    CAMLreturn(Val_int(result));
}

extern "C" CAMLprim void re2i_dump_state(value state)
{
    CAMLparam1(state);
    assert(Is_custom(state));
    DFAState *s = state_val(state);
    if (!s)
      caml_invalid_argument("Regex DFA state expected");
    std::cerr << Prog::DumpState(s) << "\n";
    CAMLreturn0;
}

static value convertState(char const* param)
{
    CAMLparam0 ();
    CAMLlocal1(result);
    DFAState *s = const_cast<DFAState*>(reinterpret_cast<DFAState const*>(param));
    if (!s)
      caml_invalid_argument("Regex DFA state expected");
    result = alloc_custom(&state_ops, sizeof(DFAState*), 1, 10000);
    state_val(result) = s;
    CAMLreturn(result);
}

extern "C" CAMLprim value re2i_explore_state(value longestmatch, value prog, value state)
{
    CAMLparam3(longestmatch, prog, state);
    CAMLlocal1(result);

    TRYCATCH (
    if (Long_val(re2i_classify_state(state)) == Generic) {
	assert(Is_long(longestmatch));
	assert(Is_custom(prog));

	DFAState *s = state_val(state);
	Prog* p = prog_val(prog);

	DFAState *transitions[258];
	if (!p->ExploreState(Bool_val(longestmatch) ? Prog::kLongestMatch : Prog::kFirstMatch, s, transitions)) {
            caml_failwith("Unable to explore DFA state");
	}
	transitions[257] = 0;
	result = caml_alloc_array(convertState, reinterpret_cast<const char**>(const_cast<DFAState const**>(transitions)));
    } else {
	result = Atom(0);
    }
    )
    CAMLreturn(result);
}
