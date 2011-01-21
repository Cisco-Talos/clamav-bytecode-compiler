(**************************************************************************)
(*  ClamAV Bytecode Compiler : compile LLVM bytecode to ClamAV bytecode.  *)
(*                                                                        *)
(*  Copyright (C) 2010 - 2011 Sourcefire, Inc.                            *)
(*                                                                        *)
(*  Authors: Török Edwin                                                *)
(*                                                                        *)
(*  This program is free software; you can redistribute it and/or modify  *)
(*  it under the terms of the GNU General Public License version 2 as     *)
(*  published by the Free Software Foundation.                            *)
(*                                                                        *)
(*  This program is distributed in the hope that it will be useful,       *)
(*  but WITHOUT ANY WARRANTY; without even the implied warranty of        *)
(*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *)
(*  GNU General Public License for more details.                          *)
(*                                                                        *)
(*  You should have received a copy of the GNU General Public License     *)
(*  along with this program; if not, write to the Free Software           *)
(*  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,            *)
(*  MA 02110-1301, USA.                                                   *)
(**************************************************************************)

open OUnit;
open Unix;
open Llvm;
open Common;

Linksection.emit_all.val := True;

value list_dir dirname =
  let dir = opendir dirname in
  let l = ref [] in do {
  try
    while True do {
       let file = dirname ^ (readdir dir) in
       if Filename.check_suffix file ".ll" then
         l.val := [file :: l.val]
       else ();
    };
  with [End_of_file -> ignore ()];
  closedir dir;
  l.val
  };

value setup_compiler file () = do {
  let (bcfile, ch1) = Filename.open_temp_file "ounit-" ".bc";
  let (cbcfile, ch2) = Filename.open_temp_file "ounit-" ".cbc";
  close_out ch1;
  close_out ch2;
  (file, bcfile, cbcfile);
};

value teardown_compiler (_, bcfile, cbcfile) = do {
  Sys.remove bcfile;
  Sys.remove cbcfile;
};

value (tmpoutname, tmpout) = Filename.open_temp_file "ounit-llvmas" "stdout_err";
value tmpout_descr = descr_of_out_channel tmpout;

at_exit (fun () -> do { close_out tmpout; ignore (Sys.remove tmpoutname);});

value test_compiler (file,bc,cbc) = do {
  ignore (alarm 2);
  ftruncate tmpout_descr 0;
  let pid = create_process "obj/Release+Asserts/bin/llvm-as"
    [|"llvm-as"; (file) ; "-o"; bc|] stdin tmpout_descr tmpout_descr in
  match Unix.waitpid [] pid with
  [ (_, WEXITED 0) ->
    try
      Compiler.compile bc cbc;
    with
    [ NotSupported (_, _) -> skip_if True "Test uses unsupported features"
    | UndefError (_,_) -> skip_if True "Test uses undefined values"
    | LogicError (_, _) -> skip_if True "Test uses unexpected features"
    | NotSupportedYet (str, _) as e ->
        let base = Filename.basename file in
        if base = "2007-04-25-AssemblerFoldExternWeak.ll" then
          ()
        else
          todo str
    ]
  | (_, WEXITED 1) -> ()
  | (_, (WEXITED _|WSTOPPED _|WSIGNALED _)) ->
      assert_bool "llvm-as crashed" False
  ];
};

(* test various parsers *)
value check_file file =
  let check_inst i =
    ignore (Debug.source_location i file)
  and check_meta meta =
    ignore (Debug.parse_descriptor meta)
  and themodule = Compiler.load_module context file in do {
    (* check debug location printers *)
    iter_functions (iter_blocks (iter_instrs check_inst)) themodule;
    (* check metadata parsers *)
    Array.iter check_meta (get_named_metadata themodule "llvm.dbg.sp");
    Array.iter check_meta (get_named_metadata themodule "llvm.dbg.gv");

    dispose_module themodule;
  };

value test_check (file,bc,_) = do {
  ignore (alarm 2);
  ftruncate tmpout_descr 0;
  let pid = create_process "obj/Release+Asserts/bin/llvm-as"
    [|"llvm-as"; (file) ; "-o"; bc|] stdin tmpout_descr tmpout_descr in
  match Unix.waitpid [] pid with
  [ (_, WEXITED 0) ->
    try
      check_file bc
    with
    [ FormatError _ as e ->
      let base = Filename.basename file in
      if base = "legalize-dbg-value.ll" then
        ignore ()
      else
        raise e
    ]
  | (_, WEXITED 1) -> ()
  | (_, (WEXITED _|WSTOPPED _|WSIGNALED _)) ->
      assert_bool "llvm-as crashed" False
  ];
};

value context = global_context ();
value i32 = i32_type context;
value m = create_module context "test-module";

value test_gep t values result () = do {
  let g = declare_global t "gtest" m;
  let expr = const_gep g (Array.map (const_int i32) values);
  assert_equal ~msg:"gep result" ~printer:Int64.to_string
    result (Layout.evaluate_gep expr 0L);
  delete_global g;
};

(* type, indexes, offset in bytes *)
value gep_tests = [
  (array_type (i8_type context) 4, [|0; 1|], 1L);
  (struct_type context [|
    (array_type (i16_type context) 4);
    (struct_type context [|i64_type context|])
  |], [|0; 0; 3|], 6L);
  (struct_type context [|
    (array_type (i16_type context) 4);
    (struct_type context [|i32_type context; i8_type context|])
  |], [|0; 1; 1|], 12L)
];

value llvm_tests subdir =
  ("llvm-" ^ subdir ^ "-tests")>:::
  (List.flatten (List.map
  (fun file ->
    let basename = Filename.basename file in
    [(basename ^ "-compile") >:: bracket (setup_compiler file) test_compiler
      teardown_compiler;
    (basename ^ "-check") >:: bracket (setup_compiler file) test_check
    teardown_compiler])
  (list_dir ("3rdparty/llvm-2.8/test/"^subdir^"/"))));

value suite_llvm1 = llvm_tests "Assembler";
value suite_llvm2 = llvm_tests "CodeGen/Generic";

value suite1 = "layout-tests">:::
  (List.map
  (fun (t, values, result) ->
    let name = (string_of_lltype t)^(Int64.to_string result) in
    name >:: test_gep t values result;)
  gep_tests);

Sys.signal 14 (Sys.Signal_handle (fun _ -> failwith "test timed out"));
run_test_tt_main (
  "clambc">:::
    [suite1;
     suite_llvm1;
     suite_llvm2
    ]);
(* vim: set sw=2: *)
