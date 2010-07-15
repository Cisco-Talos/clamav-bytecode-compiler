(* Copyright (c) 2010 Sourcefire, Inc. All rights reserved.
 * Author: Török Edvin
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *   * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *)
open Re2transform;;

let compile regex =
  parse_compile_regex [] false true false regex;;

let sraw pattern =
    let parsed = parse_regex [] pattern in
   let compiled = compile_regex false true parsed in
   let rs = prog_startrawstate false compiled in
   let ys = explore_raw_state false compiled rs in
   (rs, ys);;

(*let foo_prog = compile_regex false true (parse_regex [] "foo");;
let foo_s = prog_startrawstate false foo_prog;;
let foo_s1 = explore_raw_state false foo_prog foo_s;;
let foo_s1_p1 = foo_s1.(int_of_char 'f');;
let foo_s2 = explore_raw_state false foo_prog foo_s1_p1;;
let foo_s2_p1 = foo_s2.(int_of_char 'o');;
let foo_s3 = explore_raw_state false foo_prog foo_s2_p1;;
let foo_s3_p1 = foo_s3.(int_of_char 'o');;*)

let foor = compile "foo";;
(*let foo1 = (next_state (next_state foor 'f') 'o');;
let foof = (next_state (next_state (next_state foor 'f') 'o') 'o');;
let foox = (next_state foof 'x');;*)
let _ =
        Printexc.record_backtrace true;
        next_state foor;;
