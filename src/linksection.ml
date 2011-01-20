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
open Sectiontypes;
open Common;
open Llvm.TypeKind;

type modulekind =
    [ StdAPIModule (* implemented in C and linked with libclamav *)
    | AddOnModule (* implemented in C in an optional addon to libclamav *)
    | BytecodeModule (* implemented in another bytecode *)
    | ExportedModule (* exported from this bytecode for others to use *)
    ];

type linked_module = {
    name: string;
    kind: modulekind;
};

type kind = [ Imported | Exported | Internal];

type t = {
    functions: Hashtbl.t llvalue (kind * int);
};

value compute_function_hash name function_type =
  let h = Cryptokit.Hash.md5 () in
  let buf = Buffer.create 16 in
  let rec add_type_hash visited ty = do {
    let foldpos l a = if l = ty then 1 else if a = 0 then 0 else (a+1) in
    let recpos = List.fold_right foldpos visited 0 in
    if recpos > 0 then do {
      Buffer.add_char buf '\\';
      Buffer.add_string buf (string_of_int recpos);
    }
    else let new_visited = [ty :: visited] in
    match classify_type ty with
    [ Void -> Buffer.add_char buf 'v'
    | Integer -> do {
      Buffer.add_char buf 'i';
      Buffer.add_string buf (string_of_int (integer_bitwidth ty));
      }
    | Struct -> do {
      Buffer.add_char buf '{';
      Array.iter (fun t -> do {
          add_type_hash new_visited t;
          Buffer.add_char buf ','
        }) (struct_element_types ty);
      Buffer.add_char buf '}';
     }
    | Array -> do {
      Buffer.add_char buf '[';
      Buffer.add_string buf (string_of_int (array_length ty));
      Buffer.add_char buf 'x';
      add_type_hash new_visited (element_type ty);
      Buffer.add_char buf ']';
      }
    | Pointer -> do {
       add_type_hash new_visited (element_type ty);
       Buffer.add_char buf '*';
      }
    | Opaque -> raise (NotSupported "opaque types" (Ty ty))
    | Vector -> raise (NotSupported "Vector types" (Ty ty))
    | Float | Double | X86fp80 | Fp128 | Ppc_fp128 ->
        raise (NotSupported "Floating point types" (Ty ty))
    | Function ->
        raise (NotSupported "Function pointers as parameters" (Ty ty))
    | Label | Metadata -> assert False
    ];
  } in
  do {
    h#add_string name;
    assert ((classify_type function_type) == Function);
    add_type_hash [] (return_type function_type);
    Buffer.add_char buf ' ';
    Array.iter (add_type_hash []) (param_types function_type);
    h#add_string (Buffer.contents buf);
    let result = h#result;
(*    Printf.printf "function %s: %s\n" name (Cryptokit.transform_string
      (Cryptokit.Hexa.encode ()) result);*)
    result;
  };

value hashtbl_get hash element creator =
  try
    Hashtbl.find hash element
  with
  [ Not_found ->
    let result = creator () in do {
      Hashtbl.add hash element result;
      result;
    }
  ];

value re_dot = Str.regexp ".";

(* TODO: check that the called functions actually exist,
 * we'll need a fake .cbc that exports all the standard APIs *)
value link_function imports hash section f =
    (* all functions are in a section, only internal functions are not, easier
     * to catch unintended external calls / typoes *)
    match Str.bounded_split re_dot section 2 with
    [ [] -> do {
      Diag.report_error "Undefined reference to external function" f;
      (StdAPIModule, "undef")
      }
    | ["api" :: [name]] -> (StdAPIModule, name)
    | ["addon" :: [name]] -> (AddOnModule, name)
    | ["bc" :: [name]] -> (BytecodeModule, name)
    | [ _ :: _] -> raise (LinkerError "Unrecognized module category" f)
    ];

value starts_with str prefix =
  let n = String.length prefix in
  if (String.length str) >= n then
    (String.sub str 0 n) = prefix
  else
    False;

value emit_all = ref False;

value link_module file m =
  let import_functions = Hashtbl.create 32 in
  let export_functions = Hashtbl.create 32 in
  let internal_functions = Queue.create () in
  let function_ids = Hashtbl.create 32 in

  let handle_function_decl f = do {
    assert ((classify_value f) = ValueKind.Function);
    let name = value_name f;
    if ((use_begin f) <> None || name = "main" || name = "entrypoint" ||
        emit_all.val) &&
       not (starts_with name "llvm.dbg") then
      let lnk = linkage f in
      let is_decl = is_declaration f in
      let f_section = section f in
      let imports = is_decl || lnk = Linkage.Available_externally in
      let exports = not is_decl && lnk = Linkage.External &&
        (String.length f_section)>0 in do {
      if (imports || exports) then
        let hash = compute_function_hash (value_name f) (element_type (type_of f)) in
        let moduleid = link_function imports hash f_section f in
        let map = if imports then import_functions else export_functions in
        let functions = hashtbl_get map moduleid Queue.create in
        Queue.add (f, hash) functions
      else if (not is_decl) then
        Queue.add f internal_functions
      else ()
        }
    else ()
  }

  and write_link_module kind (modulekind, modulename) functions id =
    let write_link_function kind id (f, hash) = do {
      assert ((String.length hash) == 16);
      Encode.add_string file hash;
      Hashtbl.add function_ids f (kind, id);
      id + 1;
    } in
    let kind_id = match modulekind with
    [ ExportedModule -> 0L
    | StdAPIModule -> 1L
    | AddOnModule -> 2L
    | BytecodeModule -> 3L
    ] in do {
      match modulekind with
      [ ExportedModule -> assert (kind == Exported)
      | StdAPIModule | AddOnModule | BytecodeModule -> assert (kind == Imported)
      ];
      Encode.add_bits file kind_id 5;
      Encode.add_bits_vbr file (Int64.of_int (Queue.length functions));
      Encode.add_bits file 0L 5; (* reserved *)
      Encode.add_string_varlength file modulename;
      Queue.fold (write_link_function kind) id functions;
    }

  and handle_internal (id, flist) f = do {
    Hashtbl.add function_ids f (Internal, id);
    (id + 1, [f :: flist]);
  }

  in do {
    iter_functions handle_function_decl m;

    let lastid_imp =
      (Hashtbl.fold (write_link_module Imported) import_functions 0) in
    let lastid_exp =
      (Hashtbl.fold (write_link_module Exported) export_functions lastid_imp) in
    let (maxid, functions) = Queue.fold handle_internal (lastid_exp, []) internal_functions in
    (maxid, functions, function_ids);
  };
(* vim: set sw=2: *)
