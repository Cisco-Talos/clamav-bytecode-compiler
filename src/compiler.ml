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

open Llvm;
open Llvm_bitreader;
open Llvm_ipo;
open Llvm_scalar_opts;
open Llvm_target;
open Common;
open Sectiontypes;

exception ModuleError of string;
value handle_global ds v =
  try
    ignore (Datasection.add_global ds v);
  with
  [ NotSupported _ as e ->
    raise e
  ];

value handle_function code f =
  try do {
    Codesection.begin_function code f;
    iter_blocks (Codesection.emit_block code f) f;
    Codesection.end_function code f;
  }
  with
  [ NotSupported _ as e ->
    raise e
  ];

value load_module context file =
  parse_bitcode context (MemoryBuffer.of_file file);

Linksection.emit_all.val := True;(* TODO *)
Printexc.record_backtrace True;

value compile file out =
     let f = Encode.create_file ~name:"BC.test" ~flags:"" ~logical_sig:"lsig" ~min_func:0 ~max_func:0
~sigmaker:"sigmaker" ~out:(open_out_bin out) in
     let the_module = load_module context file in (*TODO: handle load error *)
     try
       let pm = PassManager.create ()
       in
         (
          Llvm_analysis.assert_valid_module the_module;
          let (* Set up  optimizer pipeline *) td =
            TargetData.create
              "e-p:64:8:8-i1:8:8-i8:8:8-i16:16:16-i32:32:32-i64:64:64:a0:0:64";
          TargetData.add td pm;
          add_global_optimizer pm;
          add_aggressive_dce pm;
          add_memory_to_register_demotion pm;
          ignore (PassManager.run_module the_module pm);

          Encode.new_section f SectionDataInit;
          let ds = Datasection.create f in do {
            iter_globals (handle_global ds) the_module;
            Encode.set_global_bytes f (Datasection.get_global_bytes ds);
          };
          PassManager.dispose pm;
          Encode.end_section f;

          Encode.new_section f SectionLink;
          let (max_funcid, functions, functionids) = Linksection.link_module f the_module;
          Encode.set_functions f (List.length functions) max_funcid;
          Encode.end_section f;

          Encode.new_section f SectionCode;
          let len = List.length functions in
          let code = Codesection.create f max_funcid functionids len in do {
            List.iter (handle_function code) functions;
            Codesection.finish code;
          };
          Encode.end_section f;

          Sourcesection.embed_source f the_module;

          Encode.end_file f;

          dispose_module the_module;
          (* FIXME: shouldn't allow disposing of global context *)
(*          dispose_context context;*)
          TargetData.dispose td;
          );
     with
     [ Internal (msg, bt, loc, err) as e -> do {
       Debug.print_location file the_module loc "Internal Compiler Error";
       match loc with
       [ Val v -> do {
         prerr_string "\tdumping value:";
         prerr_newline ();
         dump_value v;
         }
       | Ty t -> do {
         prerr_string "\tdumping type:\n";
         prerr_string (string_of_lltype t);
         prerr_newline ();
         }
       | Mod m -> do {
         prerr_string "\tunknown location\n";
         }
       ];
       prerr_string (Printexc.to_string err);
       prerr_newline ();
       match bt with
       [ None -> ()
       | Some trace -> prerr_string trace
       ];
       prerr_newline ();
       raise err;
       }
     ];
(* vim: set sw=2: *)
