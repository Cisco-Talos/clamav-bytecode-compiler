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

open Debug;
open Common;
open Llvm;
open Sectiontypes;

value embed_source file m = do {
  match lookup_global "__Copyright" m with
  [ None -> do {
    Encode.new_section file SectionSource;
    let space_start = Str.regexp "^[ \t]+" in
    let space_end = Str.regexp "[ \t]+$" in
    match module_location "" True m "" with
    [ {vloc = {directory=dir; filename=filename}; accurate = True} ->
      let f = open_in (Filename.concat dir filename) in
      try
        while True do {
        let line = input_line f in
        let line = Str.replace_first space_start " " line in
        let line = Str.replace_first space_end "" line in do {
          Encode.add_string file line;
        };
        Encode.add_char file '\n';
        }
      with [End_of_file -> close_in f]
      | { accurate = False } ->
          Diag.warn "Source file not found in metadata"
    ];
    }
  | Some g -> do {
      Encode.new_section file SectionCopyright;
      if (is_declaration g) then
        raise (NotSupported "__Copyright declaration without copyright text" (Val g))
      else let gep = global_initializer g in do {
        assert ((num_operands gep) == 3);
        let str = operand gep 0;
        assert (not (is_declaration g));
        let str = global_initializer str;
        for i = 0 to (array_length (type_of str)) -1 do {
          let c = Char.chr (Int64.to_int (Layout.get_const_value (operand str i))) in
          Encode.add_char file c;
        };
      }
    }
  ];
  Encode.end_section file;
};

(* vim: set sw=2: *)
