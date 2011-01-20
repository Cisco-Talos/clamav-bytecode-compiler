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

type constdesc = [ ConstTableOffset of int | ConstZeroLength of int ];

type t = {
  (* constant table *)
  offset : mutable int64;
  table: Hashtbl.t llvalue int64;
  file: Encode.bytecode_file;
};

value get_global_bytes ds = Int64.to_int ds.offset;

value create file = {offset = 0L; table = Hashtbl.create 4096; file=file};

value add_global section global =
  let queue = Queue.create () in

  let rec calculate_ptr c = match classify_value c with
  [ ValueKind.ConstantExpr ->
    match constexpr_opcode c with
    [ Opcode.GetElementPtr ->
      Layout.evaluate_gep c (get_global_offset (operand c 0))
    | Opcode.BitCast ->calculate_ptr (operand c 0 )
    | Opcode.IntToPtr ->
        raise (NotSupported "Pointers constructed from integers" (Val global))
    | _ -> raise (NotSupportedYet "Complicated constant initializers" (Val global))
    ]
  | ValueKind.GlobalAlias -> raise (NotSupported "Aliases" (Val global))
  | ValueKind.GlobalVariable -> get_global_offset c
  | ValueKind.Function -> raise (NotSupported "Function pointers" (Val global))
  | ValueKind.ConstantPointerNull -> 0L
  | ValueKind.Instruction | ValueKind.UndefValue | ValueKind.ConstantVector |
    ValueKind.ConstantStruct | ValueKind.ConstantInt | ValueKind.ConstantFP |
    ValueKind.ConstantArray | ValueKind.ConstantAggregateZero | ValueKind.InlineAsm |
    ValueKind.BasicBlock | ValueKind.Argument | ValueKind.BlockAddress|
    ValueKind.MDString| ValueKind.MDNode| ValueKind.NullValue ->
      assert False (* these are not pointers *)
  ]
  and get_global_offset g =
    try
      Hashtbl.find section.table g
    with [Not_found ->
      let t = type_of g in
      match classify_value g with
      [ ValueKind.GlobalVariable -> do {
          assert ((classify_type t) = TypeKind.Pointer);
          let result = section.offset;
          Layout.check_type (element_type t);
          let size = Layout.typesize (element_type t);
          Hashtbl.add section.table g result;
          Queue.add (g, size) queue;
          section.offset := Int64.add section.offset size;
          result;
      }
      | ValueKind.GlobalAlias -> raise (NotSupported "Aliases" (Val global))
      | _ -> assert False
      ]
    ] in

  let rec write_constant_bytes kind t c = do {
    if is_null c then do {
      let size = Layout.typesize t;
      Encode.add_zeroes section.file size;
      Int64.to_int size;
    } else match kind with
    [ TypeKind.Integer -> do {
      if (classify_value c) = ValueKind.ConstantExpr then
        if Layout.check_intptr c then
          raise (NotSupported "Integer to pointer conversion" (Val global))
        else
          raise (NotSupportedYet "Integer constant expressions as initializers"
          (Val global))
      else
        Encode.add_bits section.file (Layout.get_const_value c)
        (integer_bitwidth t);
      (integer_bitwidth t)/8;
      }
    | TypeKind.Pointer -> do {
        if (classify_value c) = ValueKind.ConstantExpr then
          if Layout.check_intptr c then
            raise (NotSupported "Integer to pointer conversion" (Val global))
          else ()
        else ();
        let p = calculate_ptr c;
        if (Int64.shift_right_logical p 32) <> 0L then
          raise (OutOfBounds "Constant expression index" (Val c))
        else
          Encode.add_pointer section.file Encode.PtrGlobal (Int64.to_int p);
        8;
      }
    | TypeKind.Struct -> do {
        let etypes = struct_element_types t;
        let s = ref 0;
        for i = 0 to (Array.length etypes)-1 do {
          let t = etypes.(i) in
          s.val := s.val + write_constant_bytes (classify_type t) t (operand c i);
        };
        s.val
      }
    | TypeKind.Array -> do {
        let etype = element_type t;
        let ekind = classify_type etype;
        let s = ref 0;
        for i = 0 to (array_length t)-1 do {
          s.val := s.val + write_constant_bytes ekind etype (operand c i)
        };
        s.val
      }
    | _ -> assert False
    ];
  } in

  let emit_global_init (g, size) =
    if is_declaration g then
      ignore (Encode.add_zeroes section.file size)
    else
      let init = global_initializer g in
      let t = type_of init in do {
        Layout.check_type t;
        let written = write_constant_bytes (classify_type t) t
        (global_initializer g) in do {
        assert ((Int64.of_int written) = size);
        }
    }

  and result = get_global_offset global in do {
    Queue.iter emit_global_init queue;
    result;
  };

(* vim: set sw=2: *)
