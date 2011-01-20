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
open Llvm_target;
open Common;
open Int64;

(* types *)
type constdesc = [ ConstTableOffset of int | ConstZeroLength of int ];

(* code *)
(* we must match with what we have in libclamav: we use a fixed targetdata for
 * all architectures, and in the libclamav <-> bytecode API we only pass
 * types that are the same on all architectures *)
value thetd = TargetData.create
"e-p:64:64:64-i1:8:8-i8:8:8:8-i16:16:16-i32:32:32-i64:64:64:a0:0:64:s0:64:64";

value rec check_type t =
    match classify_type t with
    [ TypeKind.Void  | TypeKind.Label | TypeKind.Metadata | TypeKind.Opaque ->
      raise (LogicError "Can't use unsized type" (Ty t))
    | TypeKind.Float | TypeKind.Double | TypeKind.X86fp80 | TypeKind.Fp128 |
      TypeKind.Ppc_fp128 ->
      raise (NotSupported "Floating point types" (Ty t))
    | TypeKind.Vector -> raise (NotSupported "Vector types" (Ty t))
    | TypeKind.Function -> raise (NotSupported "Function type in global" (Ty t))
    | TypeKind.Integer  | TypeKind.Pointer ->
      if (abi_size thetd t) = 0L then
        raise (LogicError "Can't allocate types with zero size" (Ty t))
      else ()
    | TypeKind.Struct ->
        Array.iter check_type (struct_element_types t)
    | TypeKind.Array ->
        check_type (element_type t)
    ];

value check_target td =
  let tdstr = TargetData.as_string td in
  if (byte_order td) <> Llvm_target.Endian.Little then
    raise (ConfigError "byte order must be little endian" tdstr)
  else if pointer_size td <> 8 or (integer_bitwidth (intptr_type td)) <> 64 then
    raise (ConfigError "pointer must be 64 bits" tdstr)
  else if (tdstr <> (TargetData.as_string thetd)) then
    raise (ConfigError "different targetdata" tdstr)
  else ();

value get_const_value v = match int64_of_const v with
  [ Some v -> v
  | None -> assert False];

value evaluate_gep c off = do {
  assert (classify_value c = ValueKind.ConstantExpr);
  let rec evaluate_gep_r t c i off =
    if (num_operands c) = i then
      off
    else let v = get_const_value (operand c i) in
    match classify_type t with
    [ TypeKind.Integer -> assert False
    | TypeKind.Struct -> do {
      let new_offset = add off (offset_of_element thetd t (to_int v)) in
      evaluate_gep_r (struct_element_types t).(to_int v) c (i+1) new_offset
      }
    | TypeKind.Array -> do {
        let element_type = element_type t in
        let new_offset = add off (mul v (abi_size thetd element_type)) in
        evaluate_gep_r element_type c (i+1) new_offset
      }
    | TypeKind.Void | TypeKind.Label | TypeKind.Metadata | TypeKind.Opaque |
      TypeKind.Float | TypeKind.Double | TypeKind.X86fp80 | TypeKind.Fp128 |
      TypeKind.Ppc_fp128 | TypeKind.Vector | TypeKind.Function |
      TypeKind.Pointer -> assert False
    ];
 let t = element_type (type_of (operand c 0));
 let start = mul (get_const_value (operand c 1)) (abi_size thetd t);
 evaluate_gep_r t c 2 (add off start);
};

value typesize = abi_size thetd;
value typesize_bits ty =
  if (classify_type ty) = TypeKind.Void then
    0_L
  else size_in_bits thetd ty;

value rec check_intptr c =
  match constexpr_opcode c with
  [ Opcode.GetElementPtr | Opcode.PtrToInt | Opcode.BitCast -> check_intptr (operand c 0)
  | Opcode.IntToPtr -> True
  | _ -> False];
(* vim: set sw=2: *)
