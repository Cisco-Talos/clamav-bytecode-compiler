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
open Common;

value md_dbg_id = mdkind_id Common.context "dbg";

type accuracy = [ Accurate | Approximate ];

type unique_block = [Empty | Unique of llbasicblock | Multiple ];

value get_unique_pred_block block =
  if block == (entry_block (block_parent block)) then None
  else let folder unique_block use = do {
    if ((classify_value (user use)) = ValueKind.Instruction) then
      let p = instr_parent (user use) in
      match unique_block with
      [ Empty -> Unique p
      | Unique u -> if u == p then unique_block else Multiple
      | Multiple -> Multiple]
    else unique_block
  } in
  match fold_left_uses folder Empty (value_of_block block) with
  [ Empty | Multiple -> None
  | Unique u -> if u == block then None else Some u ];


value llvm_debug_version = 0x80000;
value llvm_tag_block = llvm_debug_version + 11;
value llvm_tag_cu = llvm_debug_version + 17;
value llvm_tag_file = llvm_debug_version + 41;
value llvm_tag_subprog = llvm_debug_version + 46;
value llvm_tag_global = llvm_debug_version + 52;

type namedesc = {
  context: descriptor;
  name: string;
  displayname: string;
  linkagename: string;
  file: option tag_file;
  line: int;
  ty: descriptor;
  static: bool;
  not_extern: bool;
}
and sourceloc = {
  filename: string;
  directory: string;
}
and tag_lexical_block = {
  lex_context: descriptor;
  lex_line: int;
  lex_col: int;
}
and tag_subprogram = {
  sp_name: namedesc;
  virtuality: int;
  virtual_index: int;
  vtable: descriptor;
  artificial: bool;
  optimized: option bool;
}
and tag_file = {
  location: sourceloc;
  compile_unit: option tag_compileunit;
}
and tag_compileunit = {
  dwarf_lang: int;
  loc :sourceloc;
  producer: string;
  main: bool;
  is_optimized: bool;
  flags: string;
  version: int;
}
and tag_globalvar = {
  gv_name : namedesc;
  global: llvalue;
}
and descriptor =
  [ LexicalBlock of tag_lexical_block
  | SubProgram of tag_subprogram
  | File of tag_file
  | CompileUnit of tag_compileunit
  | GlobalVar of tag_globalvar
  | UnknownDesc of int
  | NullDescriptor
  ];

type location_desc = {
  srcline: int;
  srccol: int;
  scope: descriptor;
  inlined_at: option location_desc;
};

type val_location = {
  vloc: sourceloc;
  func: string;
  lineno: option int;
  col: option int;
  accurate: bool;
};

value get_i32 c = match int64_of_const c with
  [ None -> assert False
  | Some i -> Int64.to_int i];

value get_string c = match get_mdstring c with
 [ None -> raise (FormatError "Wrong metadata" (Some c))
 | Some s -> s];

value get_bool c = match get_i32 c with
 [ 0 -> False
 | -1 -> True
 | _ -> raise (FormatError "Boolean metadata expected" (Some c))
 ];

value parse_opt f c =
  if classify_value c = ValueKind.NullValue then None else Some (f c);

value rec parse_descriptor meta =
  let vclass = classify_value meta in
  if vclass = ValueKind.NullValue then NullDescriptor
  else do {
    assert ((num_operands meta) > 1);
    let thetag = get_i32 (operand meta 0) in
    match thetag with
    [ tag when tag = llvm_tag_cu -> do {
      assert ((num_operands meta) >= 10);
      CompileUnit
      {dwarf_lang = get_i32 (operand meta 2);
      loc = {
        filename = get_string (operand meta 3);
        directory = get_string (operand meta 4)
      };
      producer = get_string (operand meta 5);
      main = get_bool (operand meta 6);
      is_optimized = get_bool (operand meta 7);
      flags = get_string (operand meta 8);
      version = get_i32 (operand meta 9)
    }}
    | tag when tag = llvm_tag_file -> do {
      assert ((num_operands meta) >= 4);
      File
      {location={
        filename = get_string (operand meta 1);
        directory = get_string (operand meta 2);
      };
      compile_unit = match parse_descriptor (operand meta 3) with
      [ CompileUnit cu -> Some cu
      | LexicalBlock _| SubProgram _| File _| UnknownDesc _ | GlobalVar _->
          raise (FormatError "compileunit expected" (Some meta))
      | NullDescriptor -> None
      ]}}
    | tag when tag = llvm_tag_subprog -> do {
      if ((num_operands meta) < 15) then
        raise (FormatError "tag_subprogram 15 operands expected" (Some meta))
      else SubProgram
      {sp_name = {
        context = parse_descriptor (operand meta 2);
        name = get_string (operand meta 3);
        displayname = get_string (operand meta 4);
        linkagename = get_string (operand meta 5);
        file = match parse_descriptor (operand meta 6) with
        [ File f -> Some f
        | CompileUnit _| LexicalBlock _| SubProgram _| UnknownDesc _ |
          GlobalVar _ ->
            raise (FormatError "file expected" (Some meta))
        | NullDescriptor -> None
        ];
        line = get_i32 (operand meta 7);
        ty = parse_descriptor (operand meta 8);
        static = get_bool (operand meta 9);
        not_extern = get_bool (operand meta 10);
      };
      virtuality = get_i32 (operand meta 11);
      virtual_index = get_i32 (operand meta 12);
      vtable = parse_descriptor (operand meta 13);
      artificial = get_bool (operand meta 14);
      optimized = if (num_operands meta) >= 16 then
        Some (get_bool (operand meta 15)) else None
      }}
     | tag when tag = llvm_tag_block -> do {
       assert ((num_operands meta) >= 4);
       LexicalBlock
       {lex_context = parse_descriptor (operand meta 1);
       lex_line = get_i32 (operand meta 2);
       lex_col = get_i32 (operand meta 3);
     }}
    | tag when tag = llvm_tag_global -> do {
      if ((num_operands meta) < 12) then
        raise (FormatError "tag_global expected 12 operands" (Some meta))
      else GlobalVar
      {gv_name= {
        context = parse_descriptor (operand meta 2);
        name = get_string (operand meta 3);
        displayname = get_string (operand meta 4);
        linkagename = get_string (operand meta 5);
        file = match parse_descriptor (operand meta 6) with
        [ File f -> Some f
        | CompileUnit _| LexicalBlock _| SubProgram _| UnknownDesc _|
          GlobalVar _->
            raise (FormatError "file expected" (Some meta))
        | NullDescriptor -> None
        ];
        line = get_i32 (operand meta 7);
        ty = parse_descriptor (operand meta 8);
        static = get_bool (operand meta 9);
        not_extern = get_bool (operand meta 10);
      };
      global = (operand meta 11);
      }}
    | n -> UnknownDesc n
    ]
  };


value rec parse_metaloc meta = do {
  assert ((num_operands meta) = 4);
  {
    srcline = get_i32 (operand meta 0);
    srccol = get_i32 (operand meta 1);
    scope = parse_descriptor (operand meta 2);
    inlined_at = parse_opt parse_metaloc (operand meta 3);
  }
};

value rec get_sourceloc desc =
  match desc with
  [ LexicalBlock b -> get_sourceloc b.lex_context
  | SubProgram p ->
      match p.sp_name.file with
      [ Some f -> f.location
      | None -> get_sourceloc p.sp_name.context]
  | CompileUnit u -> u.loc
  | File f -> f.location
  | GlobalVar g ->
      match g.gv_name.file with
      [ Some f -> f.location
      | None -> get_sourceloc g.gv_name.context]
  | UnknownDesc _ | NullDescriptor ->
      raise (FormatError "Invalid metadata context" None)
  ];

value fallback_location file func =
  {
    vloc = {
      directory = Filename.dirname file;
      filename = Filename.basename file;
    };
    func = func;
    lineno = None;
    col = None;
    accurate = False;
  };

value rec source_location llval file =
  match classify_value llval with
  [ ValueKind.Instruction ->
      instr_location file Accurate llval
  | ValueKind.Function ->
      func_location file Accurate llval
  | ValueKind.GlobalVariable ->
      global_location file llval
  | ValueKind.BasicBlock ->
      block_location file Accurate (block_of_value llval)
  | _ ->
      fallback_location file (value_name llval)
  ]

and format_location instr acc desc =
  {
   vloc = get_sourceloc desc.scope;
   func = (func_location "" acc (block_parent (instr_parent instr))).func;
   lineno = Some desc.srcline;
   col = if desc.srccol > 0 then Some desc.srccol else None;
   accurate = if acc = Accurate then True else False;
  }

and block_location file acc block =
  let rec find_first_instr pos =
    match pos with
    [ At_end _ -> assert False
    | Before i ->
        let op = instr_opcode i in
        if op = Opcode.Alloca || op = Opcode.PHI then
          find_first_instr (instr_succ i)
        else
          i
    ] in
  instr_location file acc (find_first_instr (instr_begin block))

and instr_location file acc instr =
  match metadata instr md_dbg_id with
  [ Some meta -> format_location instr acc (parse_metaloc meta)
  | None ->
      match instr_pred instr with
      [ At_start block -> do {
        match get_unique_pred_block block with
        [ None -> func_location file Approximate (block_parent block)
        | Some b ->
            match instr_end b with
            [ After i -> instr_location file Approximate i
            | At_start _ -> assert False]
        ]
      }
      | After prev_instr ->
        instr_location file Approximate prev_instr
      ]
  ]

and find_meta glob name index =
  let desc = ref NullDescriptor in do {
    Array.iter (fun meta ->
      if (num_operands meta) > index then
        if (operand meta index) == glob then
          desc.val := parse_descriptor meta
        else ()
      else ()) (get_named_metadata (global_parent glob) name);
    desc.val;
  }

and module_location file acc m name =
  let a = get_named_metadata m "llvm.dbg.sp" in
  if (Array.length a > 0) then
    match parse_descriptor a.(0) with
    [ SubProgram sp as thesp ->
      {
        vloc = get_sourceloc thesp;
        func = name;
        lineno = None;
        col = None;
        accurate = acc;
      }]
  else
    fallback_location file name

and global_location file gv =
  match find_meta gv "llvm.dbg.gv" 11 with
  [ GlobalVar g as thegv ->
    {
      vloc = get_sourceloc thegv;
      func = g.gv_name.displayname;
      lineno = Some g.gv_name.line;
      col = None;
      accurate = True
    }
  | LexicalBlock _ | File _ | CompileUnit _ | SubProgram _ |
    UnknownDesc _ | NullDescriptor ->
      module_location file False (global_parent gv) (value_name gv)
  ]

and func_location file acc f =
  match find_meta f "llvm.dbg.sp" 16 with
  [ SubProgram sp as thesp ->
    {
      vloc = get_sourceloc thesp;
      func = sp.sp_name.displayname;
      lineno = Some sp.sp_name.line;
      col = None;
      accurate = if acc = Accurate then True else False
    }
  | LexicalBlock _ | File _ | CompileUnit _ | GlobalVar _ |
    UnknownDesc _ | NullDescriptor ->
      module_location file False (global_parent f) (value_name f)
  ];

value print_loc file v msg =
  let loc = source_location v file in do {
    Printf.eprintf "\n%s/%s" loc.vloc.directory loc.vloc.filename;
    match loc.lineno with
    [ Some l -> do {
      Printf.eprintf ":%d" l;
      match loc.col with
      [ Some c -> Printf.eprintf ":%d" c
      | None -> ()];}
    | None -> Printf.eprintf ":?"];
    if not loc.accurate then Printf.printf "(?)" else ();
    Printf.eprintf " in function '%s': %s\n" loc.func msg;
  };

value print_module_loc file m msg =
  let loc = module_location file True m "" in
  Printf.eprintf "\n%s/%s: %s\n" loc.vloc.directory loc.vloc.filename msg;

value print_location file m loc msg =
  match loc with
  [ Val v ->
    print_loc file v msg
  | Ty t ->
    print_module_loc file m msg
  | Mod m ->
    print_module_loc file m msg
  ];
(* vim: set sw=2: *)
