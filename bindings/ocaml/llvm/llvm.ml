(*===-- llvm/llvm.ml - LLVM Ocaml Interface --------------------------------===*
 *
 *                     The LLVM Compiler Infrastructure
 *
 * This file is distributed under the University of Illinois Open Source
 * License. See LICENSE.TXT for details.
 *
 *===----------------------------------------------------------------------===*)


type llcontext
type llmodule
type lltype
type lltypehandle
type llvalue
type lluse
type llbasicblock
type llbuilder
type llmoduleprovider
type llmemorybuffer

module TypeKind = struct
  type t =
  | Void
  | Float
  | Double
  | X86fp80
  | Fp128
  | Ppc_fp128
  | Label
  | Integer
  | Function
  | Struct
  | Array
  | Pointer
  | Opaque
  | Vector
  | Metadata
  | Union
end

module Linkage = struct
  type t =
  | External
  | Available_externally
  | Link_once
  | Link_once_odr
  | Weak
  | Weak_odr
  | Appending
  | Internal
  | Private
  | Dllimport
  | Dllexport
  | External_weak
  | Ghost
  | Common
  | Linker_private
end

module Visibility = struct
  type t =
  | Default
  | Hidden
  | Protected
end

module CallConv = struct
  let c = 0
  let fast = 8
  let cold = 9
  let x86_stdcall = 64
  let x86_fastcall = 65
end

module Attribute = struct
  type t =
  | Zext
  | Sext
  | Noreturn
  | Inreg
  | Structret
  | Nounwind
  | Noalias
  | Byval
  | Nest
  | Readnone
  | Readonly
  | Noinline
  | Alwaysinline
  | Optsize
  | Ssp
  | Sspreq
  | Nocapture
  | Noredzone
  | Noimplicitfloat
  | Naked
  | Inlinehint
end

module Icmp = struct
  type t =
  | Eq
  | Ne
  | Ugt
  | Uge
  | Ult
  | Ule
  | Sgt
  | Sge
  | Slt
  | Sle
end

module Fcmp = struct
  type t =
  | False
  | Oeq
  | Ogt
  | Oge
  | Olt
  | Ole
  | One
  | Ord
  | Uno
  | Ueq
  | Ugt
  | Uge
  | Ult
  | Ule
  | Une
  | True
end

exception IoError of string

external register_exns : exn -> unit = "llvm_register_core_exns"
let _ = register_exns (IoError "")

type ('a, 'b) llpos =
| At_end of 'a
| Before of 'b

type ('a, 'b) llrev_pos =
| At_start of 'a
| After of 'b

(*===-- Contexts ----------------------------------------------------------===*)
external create_context : unit -> llcontext = "llvm_create_context"
external dispose_context : llcontext -> unit = "llvm_dispose_context"
external global_context : unit -> llcontext = "llvm_global_context"
external mdkind_id : llcontext -> string -> int = "llvm_mdkind_id"

(*===-- Modules -----------------------------------------------------------===*)
external create_module : llcontext -> string -> llmodule = "llvm_create_module"
external dispose_module : llmodule -> unit = "llvm_dispose_module"
external target_triple: llmodule -> string
                      = "llvm_target_triple"
external set_target_triple: string -> llmodule -> unit
                          = "llvm_set_target_triple"
external data_layout: llmodule -> string
                    = "llvm_data_layout"
external set_data_layout: string -> llmodule -> unit
                        = "llvm_set_data_layout"
external define_type_name : string -> lltype -> llmodule -> bool
                          = "llvm_add_type_name"
external delete_type_name : string -> llmodule -> unit
                          = "llvm_delete_type_name"
external type_by_name : llmodule -> string -> lltype option
                      = "llvm_type_by_name"
external dump_module : llmodule -> unit = "llvm_dump_module"

(*===-- Types -------------------------------------------------------------===*)
external classify_type : lltype -> TypeKind.t = "llvm_classify_type"
external type_context : lltype -> llcontext = "llvm_type_context"

(*--... Operations on integer types ........................................--*)
external i1_type : llcontext -> lltype = "llvm_i1_type"
external i8_type : llcontext -> lltype = "llvm_i8_type"
external i16_type : llcontext -> lltype = "llvm_i16_type"
external i32_type : llcontext -> lltype = "llvm_i32_type"
external i64_type : llcontext -> lltype = "llvm_i64_type"

external integer_type : llcontext -> int -> lltype = "llvm_integer_type"
external integer_bitwidth : lltype -> int = "llvm_integer_bitwidth"

(*--... Operations on real types ...........................................--*)
external float_type : llcontext -> lltype = "llvm_float_type"
external double_type : llcontext -> lltype = "llvm_double_type"
external x86fp80_type : llcontext -> lltype = "llvm_x86fp80_type"
external fp128_type : llcontext -> lltype = "llvm_fp128_type"
external ppc_fp128_type : llcontext -> lltype = "llvm_ppc_fp128_type"

(*--... Operations on function types .......................................--*)
external function_type : lltype -> lltype array -> lltype = "llvm_function_type"
external var_arg_function_type : lltype -> lltype array -> lltype
                               = "llvm_var_arg_function_type"
external is_var_arg : lltype -> bool = "llvm_is_var_arg"
external return_type : lltype -> lltype = "LLVMGetReturnType"
external param_types : lltype -> lltype array = "llvm_param_types"

(*--... Operations on struct types .........................................--*)
external struct_type : llcontext -> lltype array -> lltype = "llvm_struct_type"
external packed_struct_type : llcontext -> lltype array -> lltype
                            = "llvm_packed_struct_type"
external struct_element_types : lltype -> lltype array
                              = "llvm_struct_element_types"
external is_packed : lltype -> bool = "llvm_is_packed"

(*--... Operations on union types ..........................................--*)
external union_type : llcontext -> lltype array -> lltype = "llvm_union_type"
external union_element_types : lltype -> lltype array
                             = "llvm_union_element_types"

(*--... Operations on pointer, vector, and array types .....................--*)
external array_type : lltype -> int -> lltype = "llvm_array_type"
external pointer_type : lltype -> lltype = "llvm_pointer_type"
external qualified_pointer_type : lltype -> int -> lltype
                                = "llvm_qualified_pointer_type"
external vector_type : lltype -> int -> lltype = "llvm_vector_type"

external element_type : lltype -> lltype = "LLVMGetElementType"
external array_length : lltype -> int = "llvm_array_length"
external address_space : lltype -> int = "llvm_address_space"
external vector_size : lltype -> int = "llvm_vector_size"

(*--... Operations on other types ..........................................--*)
external opaque_type : llcontext -> lltype = "llvm_opaque_type"
external void_type : llcontext -> lltype = "llvm_void_type"
external label_type : llcontext -> lltype = "llvm_label_type"

(*--... Operations on type handles .........................................--*)
external handle_to_type : lltype -> lltypehandle = "llvm_handle_to_type"
external type_of_handle : lltypehandle -> lltype = "llvm_type_of_handle"
external refine_type : lltype -> lltype -> unit = "llvm_refine_type"


(*===-- Values ------------------------------------------------------------===*)
external type_of : llvalue -> lltype = "llvm_type_of"
external value_name : llvalue -> string = "llvm_value_name"
external set_value_name : string -> llvalue -> unit = "llvm_set_value_name"
external dump_value : llvalue -> unit = "llvm_dump_value"
external replace_all_uses_with : llvalue -> llvalue -> unit
                               = "LLVMReplaceAllUsesWith"

(*--... Operations on uses .................................................--*)
external use_begin : llvalue -> lluse option = "llvm_use_begin"
external use_succ : lluse -> lluse option = "llvm_use_succ"
external user : lluse -> llvalue = "llvm_user"
external used_value : lluse -> llvalue = "llvm_used_value"

let iter_uses f v =
  let rec aux = function
    | None -> ()
    | Some u ->
        f u;
        aux (use_succ u)
  in
  aux (use_begin v)

let fold_left_uses f init v =
  let rec aux init u =
    match u with
    | None -> init
    | Some u -> aux (f init u) (use_succ u)
  in
  aux init (use_begin v)

let fold_right_uses f v init =
  let rec aux u init =
    match u with
    | None -> init
    | Some u -> f u (aux (use_succ u) init)
  in
  aux (use_begin v) init


(*--... Operations on users ................................................--*)
external operand : llvalue -> int -> llvalue = "llvm_operand"

(*--... Operations on constants of (mostly) any type .......................--*)
external is_constant : llvalue -> bool = "llvm_is_constant"
external const_null : lltype -> llvalue = "LLVMConstNull"
external const_all_ones : (*int|vec*)lltype -> llvalue = "LLVMConstAllOnes"
external const_pointer_null : lltype -> llvalue = "LLVMConstPointerNull"
external undef : lltype -> llvalue = "LLVMGetUndef"
external is_null : llvalue -> bool = "llvm_is_null"
external is_undef : llvalue -> bool = "llvm_is_undef"

(*--... Operations on instructions .........................................--*)
external has_metadata : llvalue -> bool = "llvm_has_metadata"
external metadata : llvalue -> int -> llvalue option = "llvm_metadata"
external set_metadata : llvalue -> int -> llvalue -> unit = "llvm_set_metadata"
external clear_metadata : llvalue -> int -> unit = "llvm_clear_metadata"

(*--... Operations on metadata .......,.....................................--*)
external mdstring : llcontext -> string -> llvalue = "llvm_mdstring"
external mdnode : llcontext -> llvalue array -> llvalue = "llvm_mdnode"

(*--... Operations on scalar constants .....................................--*)
external const_int : lltype -> int -> llvalue = "llvm_const_int"
external const_of_int64 : lltype -> Int64.t -> bool -> llvalue
                        = "llvm_const_of_int64"
external const_int_of_string : lltype -> string -> int -> llvalue
                             = "llvm_const_int_of_string"
external const_float : lltype -> float -> llvalue = "llvm_const_float"
external const_float_of_string : lltype -> string -> llvalue
                               = "llvm_const_float_of_string"

(*--... Operations on composite constants ..................................--*)
external const_string : llcontext -> string -> llvalue = "llvm_const_string"
external const_stringz : llcontext -> string -> llvalue = "llvm_const_stringz"
external const_array : lltype -> llvalue array -> llvalue = "llvm_const_array"
external const_struct : llcontext -> llvalue array -> llvalue
                      = "llvm_const_struct"
external const_packed_struct : llcontext -> llvalue array -> llvalue
                             = "llvm_const_packed_struct"
external const_vector : llvalue array -> llvalue = "llvm_const_vector"
external const_union : lltype -> llvalue -> llvalue = "LLVMConstUnion"

(*--... Constant expressions ...............................................--*)
external align_of : lltype -> llvalue = "LLVMAlignOf"
external size_of : lltype -> llvalue = "LLVMSizeOf"
external const_neg : llvalue -> llvalue = "LLVMConstNeg"
external const_nsw_neg : llvalue -> llvalue = "LLVMConstNSWNeg"
external const_nuw_neg : llvalue -> llvalue = "LLVMConstNUWNeg"
external const_fneg : llvalue -> llvalue = "LLVMConstFNeg"
external const_not : llvalue -> llvalue = "LLVMConstNot"
external const_add : llvalue -> llvalue -> llvalue = "LLVMConstAdd"
external const_nsw_add : llvalue -> llvalue -> llvalue = "LLVMConstNSWAdd"
external const_nuw_add : llvalue -> llvalue -> llvalue = "LLVMConstNUWAdd"
external const_fadd : llvalue -> llvalue -> llvalue = "LLVMConstFAdd"
external const_sub : llvalue -> llvalue -> llvalue = "LLVMConstSub"
external const_nsw_sub : llvalue -> llvalue -> llvalue = "LLVMConstNSWSub"
external const_nuw_sub : llvalue -> llvalue -> llvalue = "LLVMConstNUWSub"
external const_fsub : llvalue -> llvalue -> llvalue = "LLVMConstFSub"
external const_mul : llvalue -> llvalue -> llvalue = "LLVMConstMul"
external const_nsw_mul : llvalue -> llvalue -> llvalue = "LLVMConstNSWMul"
external const_nuw_mul : llvalue -> llvalue -> llvalue = "LLVMConstNUWMul"
external const_fmul : llvalue -> llvalue -> llvalue = "LLVMConstFMul"
external const_udiv : llvalue -> llvalue -> llvalue = "LLVMConstUDiv"
external const_sdiv : llvalue -> llvalue -> llvalue = "LLVMConstSDiv"
external const_exact_sdiv : llvalue -> llvalue -> llvalue = "LLVMConstExactSDiv"
external const_fdiv : llvalue -> llvalue -> llvalue = "LLVMConstFDiv"
external const_urem : llvalue -> llvalue -> llvalue = "LLVMConstURem"
external const_srem : llvalue -> llvalue -> llvalue = "LLVMConstSRem"
external const_frem : llvalue -> llvalue -> llvalue = "LLVMConstFRem"
external const_and : llvalue -> llvalue -> llvalue = "LLVMConstAnd"
external const_or : llvalue -> llvalue -> llvalue = "LLVMConstOr"
external const_xor : llvalue -> llvalue -> llvalue = "LLVMConstXor"
external const_icmp : Icmp.t -> llvalue -> llvalue -> llvalue
                    = "llvm_const_icmp"
external const_fcmp : Fcmp.t -> llvalue -> llvalue -> llvalue
                    = "llvm_const_fcmp"
external const_shl : llvalue -> llvalue -> llvalue = "LLVMConstShl"
external const_lshr : llvalue -> llvalue -> llvalue = "LLVMConstLShr"
external const_ashr : llvalue -> llvalue -> llvalue = "LLVMConstAShr"
external const_gep : llvalue -> llvalue array -> llvalue = "llvm_const_gep"
external const_in_bounds_gep : llvalue -> llvalue array -> llvalue
                            = "llvm_const_in_bounds_gep"
external const_trunc : llvalue -> lltype -> llvalue = "LLVMConstTrunc"
external const_sext : llvalue -> lltype -> llvalue = "LLVMConstSExt"
external const_zext : llvalue -> lltype -> llvalue = "LLVMConstZExt"
external const_fptrunc : llvalue -> lltype -> llvalue = "LLVMConstFPTrunc"
external const_fpext : llvalue -> lltype -> llvalue = "LLVMConstFPExt"
external const_uitofp : llvalue -> lltype -> llvalue = "LLVMConstUIToFP"
external const_sitofp : llvalue -> lltype -> llvalue = "LLVMConstSIToFP"
external const_fptoui : llvalue -> lltype -> llvalue = "LLVMConstFPToUI"
external const_fptosi : llvalue -> lltype -> llvalue = "LLVMConstFPToSI"
external const_ptrtoint : llvalue -> lltype -> llvalue = "LLVMConstPtrToInt"
external const_inttoptr : llvalue -> lltype -> llvalue = "LLVMConstIntToPtr"
external const_bitcast : llvalue -> lltype -> llvalue = "LLVMConstBitCast"
external const_zext_or_bitcast : llvalue -> lltype -> llvalue
                             = "LLVMConstZExtOrBitCast"
external const_sext_or_bitcast : llvalue -> lltype -> llvalue
                             = "LLVMConstSExtOrBitCast"
external const_trunc_or_bitcast : llvalue -> lltype -> llvalue
                              = "LLVMConstTruncOrBitCast"
external const_pointercast : llvalue -> lltype -> llvalue
                           = "LLVMConstPointerCast"
external const_intcast : llvalue -> lltype -> llvalue = "LLVMConstIntCast"
external const_fpcast : llvalue -> lltype -> llvalue = "LLVMConstFPCast"
external const_select : llvalue -> llvalue -> llvalue -> llvalue
                      = "LLVMConstSelect"
external const_extractelement : llvalue -> llvalue -> llvalue
                              = "LLVMConstExtractElement"
external const_insertelement : llvalue -> llvalue -> llvalue -> llvalue
                             = "LLVMConstInsertElement"
external const_shufflevector : llvalue -> llvalue -> llvalue -> llvalue
                             = "LLVMConstShuffleVector"
external const_extractvalue : llvalue -> int array -> llvalue
                            = "llvm_const_extractvalue"
external const_insertvalue : llvalue -> llvalue -> int array -> llvalue
                           = "llvm_const_insertvalue"
external const_inline_asm : lltype -> string -> string -> bool -> bool ->
                            llvalue
                          = "llvm_const_inline_asm"
external block_address : llvalue -> llbasicblock -> llvalue = "LLVMBlockAddress"

(*--... Operations on global variables, functions, and aliases (globals) ...--*)
external global_parent : llvalue -> llmodule = "LLVMGetGlobalParent"
external is_declaration : llvalue -> bool = "llvm_is_declaration"
external linkage : llvalue -> Linkage.t = "llvm_linkage"
external set_linkage : Linkage.t -> llvalue -> unit = "llvm_set_linkage"
external section : llvalue -> string = "llvm_section"
external set_section : string -> llvalue -> unit = "llvm_set_section"
external visibility : llvalue -> Visibility.t = "llvm_visibility"
external set_visibility : Visibility.t -> llvalue -> unit = "llvm_set_visibility"
external alignment : llvalue -> int = "llvm_alignment"
external set_alignment : int -> llvalue -> unit = "llvm_set_alignment"
external is_global_constant : llvalue -> bool = "llvm_is_global_constant"
external set_global_constant : bool -> llvalue -> unit
                             = "llvm_set_global_constant"

(*--... Operations on global variables .....................................--*)
external declare_global : lltype -> string -> llmodule -> llvalue
                        = "llvm_declare_global"
external declare_qualified_global : lltype -> string -> int -> llmodule ->
                                    llvalue
                                  = "llvm_declare_qualified_global"
external define_global : string -> llvalue -> llmodule -> llvalue
                       = "llvm_define_global"
external define_qualified_global : string -> llvalue -> int -> llmodule ->
                                   llvalue
                                 = "llvm_define_qualified_global"
external lookup_global : string -> llmodule -> llvalue option
                       = "llvm_lookup_global"
external delete_global : llvalue -> unit = "llvm_delete_global"
external global_initializer : llvalue -> llvalue = "LLVMGetInitializer"
external set_initializer : llvalue -> llvalue -> unit = "llvm_set_initializer"
external remove_initializer : llvalue -> unit = "llvm_remove_initializer"
external is_thread_local : llvalue -> bool = "llvm_is_thread_local"
external set_thread_local : bool -> llvalue -> unit = "llvm_set_thread_local"
external global_begin : llmodule -> (llmodule, llvalue) llpos
                      = "llvm_global_begin"
external global_succ : llvalue -> (llmodule, llvalue) llpos
                     = "llvm_global_succ"
external global_end : llmodule -> (llmodule, llvalue) llrev_pos
                    = "llvm_global_end"
external global_pred : llvalue -> (llmodule, llvalue) llrev_pos
                     = "llvm_global_pred"

let rec iter_global_range f i e =
  if i = e then () else
  match i with
  | At_end _ -> raise (Invalid_argument "Invalid global variable range.")
  | Before bb ->
      f bb;
      iter_global_range f (global_succ bb) e

let iter_globals f m =
  iter_global_range f (global_begin m) (At_end m)

let rec fold_left_global_range f init i e =
  if i = e then init else
  match i with
  | At_end _ -> raise (Invalid_argument "Invalid global variable range.")
  | Before bb -> fold_left_global_range f (f init bb) (global_succ bb) e

let fold_left_globals f init m =
  fold_left_global_range f init (global_begin m) (At_end m)

let rec rev_iter_global_range f i e =
  if i = e then () else
  match i with
  | At_start _ -> raise (Invalid_argument "Invalid global variable range.")
  | After bb ->
      f bb;
      rev_iter_global_range f (global_pred bb) e

let rev_iter_globals f m =
  rev_iter_global_range f (global_end m) (At_start m)

let rec fold_right_global_range f i e init =
  if i = e then init else
  match i with
  | At_start _ -> raise (Invalid_argument "Invalid global variable range.")
  | After bb -> fold_right_global_range f (global_pred bb) e (f bb init)

let fold_right_globals f m init =
  fold_right_global_range f (global_end m) (At_start m) init

(*--... Operations on aliases ..............................................--*)
external add_alias : llmodule -> lltype -> llvalue -> string -> llvalue
                   = "llvm_add_alias"

(*--... Operations on functions ............................................--*)
external declare_function : string -> lltype -> llmodule -> llvalue
                          = "llvm_declare_function"
external define_function : string -> lltype -> llmodule -> llvalue
                         = "llvm_define_function"
external lookup_function : string -> llmodule -> llvalue option
                         = "llvm_lookup_function"
external delete_function : llvalue -> unit = "llvm_delete_function"
external is_intrinsic : llvalue -> bool = "llvm_is_intrinsic"
external function_call_conv : llvalue -> int = "llvm_function_call_conv"
external set_function_call_conv : int -> llvalue -> unit
                                = "llvm_set_function_call_conv"
external gc : llvalue -> string option = "llvm_gc"
external set_gc : string option -> llvalue -> unit = "llvm_set_gc"
external function_begin : llmodule -> (llmodule, llvalue) llpos
                        = "llvm_function_begin"
external function_succ : llvalue -> (llmodule, llvalue) llpos
                       = "llvm_function_succ"
external function_end : llmodule -> (llmodule, llvalue) llrev_pos
                      = "llvm_function_end"
external function_pred : llvalue -> (llmodule, llvalue) llrev_pos
                       = "llvm_function_pred"

let rec iter_function_range f i e =
  if i = e then () else
  match i with
  | At_end _ -> raise (Invalid_argument "Invalid function range.")
  | Before fn ->
      f fn;
      iter_function_range f (function_succ fn) e

let iter_functions f m =
  iter_function_range f (function_begin m) (At_end m)

let rec fold_left_function_range f init i e =
  if i = e then init else
  match i with
  | At_end _ -> raise (Invalid_argument "Invalid function range.")
  | Before fn -> fold_left_function_range f (f init fn) (function_succ fn) e

let fold_left_functions f init m =
  fold_left_function_range f init (function_begin m) (At_end m)

let rec rev_iter_function_range f i e =
  if i = e then () else
  match i with
  | At_start _ -> raise (Invalid_argument "Invalid function range.")
  | After fn ->
      f fn;
      rev_iter_function_range f (function_pred fn) e

let rev_iter_functions f m =
  rev_iter_function_range f (function_end m) (At_start m)

let rec fold_right_function_range f i e init =
  if i = e then init else
  match i with
  | At_start _ -> raise (Invalid_argument "Invalid function range.")
  | After fn -> fold_right_function_range f (function_pred fn) e (f fn init)

let fold_right_functions f m init =
  fold_right_function_range f (function_end m) (At_start m) init

external add_function_attr : llvalue -> Attribute.t -> unit
                           = "llvm_add_function_attr"
external remove_function_attr : llvalue -> Attribute.t -> unit
                              = "llvm_remove_function_attr"

(*--... Operations on params ...............................................--*)
external params : llvalue -> llvalue array = "llvm_params"
external param : llvalue -> int -> llvalue = "llvm_param"
external param_parent : llvalue -> llvalue = "LLVMGetParamParent"
external param_begin : llvalue -> (llvalue, llvalue) llpos = "llvm_param_begin"
external param_succ : llvalue -> (llvalue, llvalue) llpos = "llvm_param_succ"
external param_end : llvalue -> (llvalue, llvalue) llrev_pos = "llvm_param_end"
external param_pred : llvalue -> (llvalue, llvalue) llrev_pos ="llvm_param_pred"

let rec iter_param_range f i e =
  if i = e then () else
  match i with
  | At_end _ -> raise (Invalid_argument "Invalid parameter range.")
  | Before p ->
      f p;
      iter_param_range f (param_succ p) e

let iter_params f fn =
  iter_param_range f (param_begin fn) (At_end fn)

let rec fold_left_param_range f init i e =
  if i = e then init else
  match i with
  | At_end _ -> raise (Invalid_argument "Invalid parameter range.")
  | Before p -> fold_left_param_range f (f init p) (param_succ p) e

let fold_left_params f init fn =
  fold_left_param_range f init (param_begin fn) (At_end fn)

let rec rev_iter_param_range f i e =
  if i = e then () else
  match i with
  | At_start _ -> raise (Invalid_argument "Invalid parameter range.")
  | After p ->
      f p;
      rev_iter_param_range f (param_pred p) e

let rev_iter_params f fn =
  rev_iter_param_range f (param_end fn) (At_start fn)

let rec fold_right_param_range f init i e =
  if i = e then init else
  match i with
  | At_start _ -> raise (Invalid_argument "Invalid parameter range.")
  | After p -> fold_right_param_range f (f p init) (param_pred p) e

let fold_right_params f fn init =
  fold_right_param_range f init (param_end fn) (At_start fn)

external add_param_attr : llvalue -> Attribute.t -> unit
                        = "llvm_add_param_attr"
external remove_param_attr : llvalue -> Attribute.t -> unit
                           = "llvm_remove_param_attr"
external set_param_alignment : llvalue -> int -> unit
                             = "llvm_set_param_alignment"

(*--... Operations on basic blocks .........................................--*)
external value_of_block : llbasicblock -> llvalue = "LLVMBasicBlockAsValue"
external value_is_block : llvalue -> bool = "llvm_value_is_block"
external block_of_value : llvalue -> llbasicblock = "LLVMValueAsBasicBlock"
external block_parent : llbasicblock -> llvalue = "LLVMGetBasicBlockParent"
external basic_blocks : llvalue -> llbasicblock array = "llvm_basic_blocks"
external entry_block : llvalue -> llbasicblock = "LLVMGetEntryBasicBlock"
external delete_block : llbasicblock -> unit = "llvm_delete_block"
external append_block : llcontext -> string -> llvalue -> llbasicblock
                      = "llvm_append_block"
external insert_block : llcontext -> string -> llbasicblock -> llbasicblock
                      = "llvm_insert_block"
external block_begin : llvalue -> (llvalue, llbasicblock) llpos
                     = "llvm_block_begin"
external block_succ : llbasicblock -> (llvalue, llbasicblock) llpos
                    = "llvm_block_succ"
external block_end : llvalue -> (llvalue, llbasicblock) llrev_pos
                   = "llvm_block_end"
external block_pred : llbasicblock -> (llvalue, llbasicblock) llrev_pos
                    = "llvm_block_pred"

let rec iter_block_range f i e =
  if i = e then () else
  match i with
  | At_end _ -> raise (Invalid_argument "Invalid block range.")
  | Before bb ->
      f bb;
      iter_block_range f (block_succ bb) e

let iter_blocks f fn =
  iter_block_range f (block_begin fn) (At_end fn)

let rec fold_left_block_range f init i e =
  if i = e then init else
  match i with
  | At_end _ -> raise (Invalid_argument "Invalid block range.")
  | Before bb -> fold_left_block_range f (f init bb) (block_succ bb) e

let fold_left_blocks f init fn =
  fold_left_block_range f init (block_begin fn) (At_end fn)

let rec rev_iter_block_range f i e =
  if i = e then () else
  match i with
  | At_start _ -> raise (Invalid_argument "Invalid block range.")
  | After bb ->
      f bb;
      rev_iter_block_range f (block_pred bb) e

let rev_iter_blocks f fn =
  rev_iter_block_range f (block_end fn) (At_start fn)

let rec fold_right_block_range f init i e =
  if i = e then init else
  match i with
  | At_start _ -> raise (Invalid_argument "Invalid block range.")
  | After bb -> fold_right_block_range f (f bb init) (block_pred bb) e

let fold_right_blocks f fn init =
  fold_right_block_range f init (block_end fn) (At_start fn)

(*--... Operations on instructions .........................................--*)
external instr_parent : llvalue -> llbasicblock = "LLVMGetInstructionParent"
external instr_begin : llbasicblock -> (llbasicblock, llvalue) llpos
                     = "llvm_instr_begin"
external instr_succ : llvalue -> (llbasicblock, llvalue) llpos
                     = "llvm_instr_succ"
external instr_end : llbasicblock -> (llbasicblock, llvalue) llrev_pos
                     = "llvm_instr_end"
external instr_pred : llvalue -> (llbasicblock, llvalue) llrev_pos
                     = "llvm_instr_pred"

let rec iter_instrs_range f i e =
  if i = e then () else
  match i with
  | At_end _ -> raise (Invalid_argument "Invalid instruction range.")
  | Before i ->
      f i;
      iter_instrs_range f (instr_succ i) e

let iter_instrs f bb =
  iter_instrs_range f (instr_begin bb) (At_end bb)

let rec fold_left_instrs_range f init i e =
  if i = e then init else
  match i with
  | At_end _ -> raise (Invalid_argument "Invalid instruction range.")
  | Before i -> fold_left_instrs_range f (f init i) (instr_succ i) e

let fold_left_instrs f init bb =
  fold_left_instrs_range f init (instr_begin bb) (At_end bb)

let rec rev_iter_instrs_range f i e =
  if i = e then () else
  match i with
  | At_start _ -> raise (Invalid_argument "Invalid instruction range.")
  | After i ->
      f i;
      rev_iter_instrs_range f (instr_pred i) e

let rev_iter_instrs f bb =
  rev_iter_instrs_range f (instr_end bb) (At_start bb)

let rec fold_right_instr_range f i e init =
  if i = e then init else
  match i with
  | At_start _ -> raise (Invalid_argument "Invalid instruction range.")
  | After i -> fold_right_instr_range f (instr_pred i) e (f i init)

let fold_right_instrs f bb init =
  fold_right_instr_range f (instr_end bb) (At_start bb) init


(*--... Operations on call sites ...........................................--*)
external instruction_call_conv: llvalue -> int
                              = "llvm_instruction_call_conv"
external set_instruction_call_conv: int -> llvalue -> unit
                                  = "llvm_set_instruction_call_conv"
external add_instruction_param_attr : llvalue -> int -> Attribute.t -> unit
                                    = "llvm_add_instruction_param_attr"
external remove_instruction_param_attr : llvalue -> int -> Attribute.t -> unit
                                       = "llvm_remove_instruction_param_attr"

(*--... Operations on call instructions (only) .............................--*)
external is_tail_call : llvalue -> bool = "llvm_is_tail_call"
external set_tail_call : bool -> llvalue -> unit = "llvm_set_tail_call"

(*--... Operations on phi nodes ............................................--*)
external add_incoming : (llvalue * llbasicblock) -> llvalue -> unit
                      = "llvm_add_incoming"
external incoming : llvalue -> (llvalue * llbasicblock) list = "llvm_incoming"


(*===-- Instruction builders ----------------------------------------------===*)
external builder : llcontext -> llbuilder = "llvm_builder"
external position_builder : (llbasicblock, llvalue) llpos -> llbuilder -> unit
                          = "llvm_position_builder"
external insertion_block : llbuilder -> llbasicblock = "llvm_insertion_block"
external insert_into_builder : llvalue -> string -> llbuilder -> unit
                             = "llvm_insert_into_builder"

let builder_at context ip =
  let b = builder context in
  position_builder ip b;
  b

let builder_before context i = builder_at context (Before i)
let builder_at_end context bb = builder_at context (At_end bb)

let position_before i = position_builder (Before i)
let position_at_end bb = position_builder (At_end bb)


(*--... Metadata ...........................................................--*)
external set_current_debug_location : llbuilder -> llvalue -> unit
                                    = "llvm_set_current_debug_location"
external clear_current_debug_location : llbuilder -> unit
                                      = "llvm_clear_current_debug_location"
external current_debug_location : llbuilder -> llvalue option
                                    = "llvm_current_debug_location"
external set_inst_debug_location : llbuilder -> llvalue -> unit
                                 = "llvm_set_inst_debug_location"


(*--... Terminators ........................................................--*)
external build_ret_void : llbuilder -> llvalue = "llvm_build_ret_void"
external build_ret : llvalue -> llbuilder -> llvalue = "llvm_build_ret"
external build_aggregate_ret : llvalue array -> llbuilder -> llvalue
                             = "llvm_build_aggregate_ret"
external build_br : llbasicblock -> llbuilder -> llvalue = "llvm_build_br"
external build_cond_br : llvalue -> llbasicblock -> llbasicblock -> llbuilder ->
                         llvalue = "llvm_build_cond_br"
external build_switch : llvalue -> llbasicblock -> int -> llbuilder -> llvalue
                      = "llvm_build_switch"
external add_case : llvalue -> llvalue -> llbasicblock -> unit
                  = "llvm_add_case"
external build_indirect_br : llvalue -> int -> llbuilder -> llvalue
                           = "llvm_build_indirect_br"
external add_destination : llvalue -> llbasicblock -> unit
                         = "llvm_add_destination"
external build_invoke : llvalue -> llvalue array -> llbasicblock ->
                        llbasicblock -> string -> llbuilder -> llvalue
                      = "llvm_build_invoke_bc" "llvm_build_invoke_nat"
external build_unwind : llbuilder -> llvalue = "llvm_build_unwind"
external build_unreachable : llbuilder -> llvalue = "llvm_build_unreachable"

(*--... Arithmetic .........................................................--*)
external build_add : llvalue -> llvalue -> string -> llbuilder -> llvalue
                   = "llvm_build_add"
external build_nsw_add : llvalue -> llvalue -> string -> llbuilder -> llvalue
                       = "llvm_build_nsw_add"
external build_nuw_add : llvalue -> llvalue -> string -> llbuilder -> llvalue
                       = "llvm_build_nuw_add"
external build_fadd : llvalue -> llvalue -> string -> llbuilder -> llvalue
                    = "llvm_build_fadd"
external build_sub : llvalue -> llvalue -> string -> llbuilder -> llvalue
                   = "llvm_build_sub"
external build_nsw_sub : llvalue -> llvalue -> string -> llbuilder -> llvalue
                       = "llvm_build_nsw_sub"
external build_nuw_sub : llvalue -> llvalue -> string -> llbuilder -> llvalue
                       = "llvm_build_nuw_sub"
external build_fsub : llvalue -> llvalue -> string -> llbuilder -> llvalue
                    = "llvm_build_fsub"
external build_mul : llvalue -> llvalue -> string -> llbuilder -> llvalue
                   = "llvm_build_mul"
external build_nsw_mul : llvalue -> llvalue -> string -> llbuilder -> llvalue
                       = "llvm_build_nsw_mul"
external build_nuw_mul : llvalue -> llvalue -> string -> llbuilder -> llvalue
                       = "llvm_build_nuw_mul"
external build_fmul : llvalue -> llvalue -> string -> llbuilder -> llvalue
                    = "llvm_build_fmul"
external build_udiv : llvalue -> llvalue -> string -> llbuilder -> llvalue
                    = "llvm_build_udiv"
external build_sdiv : llvalue -> llvalue -> string -> llbuilder -> llvalue
                    = "llvm_build_sdiv"
external build_exact_sdiv : llvalue -> llvalue -> string -> llbuilder -> llvalue
                          = "llvm_build_exact_sdiv"
external build_fdiv : llvalue -> llvalue -> string -> llbuilder -> llvalue
                    = "llvm_build_fdiv"
external build_urem : llvalue -> llvalue -> string -> llbuilder -> llvalue
                    = "llvm_build_urem"
external build_srem : llvalue -> llvalue -> string -> llbuilder -> llvalue
                    = "llvm_build_srem"
external build_frem : llvalue -> llvalue -> string -> llbuilder -> llvalue
                    = "llvm_build_frem"
external build_shl : llvalue -> llvalue -> string -> llbuilder -> llvalue
                   = "llvm_build_shl"
external build_lshr : llvalue -> llvalue -> string -> llbuilder -> llvalue
                    = "llvm_build_lshr"
external build_ashr : llvalue -> llvalue -> string -> llbuilder -> llvalue
                    = "llvm_build_ashr"
external build_and : llvalue -> llvalue -> string -> llbuilder -> llvalue
                   = "llvm_build_and"
external build_or : llvalue -> llvalue -> string -> llbuilder -> llvalue
                  = "llvm_build_or"
external build_xor : llvalue -> llvalue -> string -> llbuilder -> llvalue
                   = "llvm_build_xor"
external build_neg : llvalue -> string -> llbuilder -> llvalue
                   = "llvm_build_neg"
external build_nsw_neg : llvalue -> string -> llbuilder -> llvalue
                       = "llvm_build_nsw_neg"
external build_nuw_neg : llvalue -> string -> llbuilder -> llvalue
                       = "llvm_build_nuw_neg"
external build_fneg : llvalue -> string -> llbuilder -> llvalue
                    = "llvm_build_fneg"
external build_not : llvalue -> string -> llbuilder -> llvalue
                   = "llvm_build_not"

(*--... Memory .............................................................--*)
external build_alloca : lltype -> string -> llbuilder -> llvalue
                      = "llvm_build_alloca"
external build_array_alloca : lltype -> llvalue -> string -> llbuilder ->
                              llvalue = "llvm_build_array_alloca"
external build_load : llvalue -> string -> llbuilder -> llvalue
                    = "llvm_build_load"
external build_store : llvalue -> llvalue -> llbuilder -> llvalue
                     = "llvm_build_store"
external build_gep : llvalue -> llvalue array -> string -> llbuilder -> llvalue
                   = "llvm_build_gep"
external build_in_bounds_gep : llvalue -> llvalue array -> string ->
                             llbuilder -> llvalue = "llvm_build_in_bounds_gep"
external build_struct_gep : llvalue -> int -> string -> llbuilder -> llvalue
                         = "llvm_build_struct_gep"

external build_global_string : string -> string -> llbuilder -> llvalue
                             = "llvm_build_global_string"
external build_global_stringptr  : string -> string -> llbuilder -> llvalue
                                 = "llvm_build_global_stringptr"

(*--... Casts ..............................................................--*)
external build_trunc : llvalue -> lltype -> string -> llbuilder -> llvalue
                     = "llvm_build_trunc"
external build_zext : llvalue -> lltype -> string -> llbuilder -> llvalue
                    = "llvm_build_zext"
external build_sext : llvalue -> lltype -> string -> llbuilder -> llvalue
                    = "llvm_build_sext"
external build_fptoui : llvalue -> lltype -> string -> llbuilder -> llvalue
                      = "llvm_build_fptoui"
external build_fptosi : llvalue -> lltype -> string -> llbuilder -> llvalue
                      = "llvm_build_fptosi"
external build_uitofp : llvalue -> lltype -> string -> llbuilder -> llvalue
                      = "llvm_build_uitofp"
external build_sitofp : llvalue -> lltype -> string -> llbuilder -> llvalue
                      = "llvm_build_sitofp"
external build_fptrunc : llvalue -> lltype -> string -> llbuilder -> llvalue
                       = "llvm_build_fptrunc"
external build_fpext : llvalue -> lltype -> string -> llbuilder -> llvalue
                     = "llvm_build_fpext"
external build_ptrtoint : llvalue -> lltype -> string -> llbuilder -> llvalue
                        = "llvm_build_prttoint"
external build_inttoptr : llvalue -> lltype -> string -> llbuilder -> llvalue
                        = "llvm_build_inttoptr"
external build_bitcast : llvalue -> lltype -> string -> llbuilder -> llvalue
                       = "llvm_build_bitcast"
external build_zext_or_bitcast : llvalue -> lltype -> string -> llbuilder ->
                                 llvalue = "llvm_build_zext_or_bitcast"
external build_sext_or_bitcast : llvalue -> lltype -> string -> llbuilder ->
                                 llvalue = "llvm_build_sext_or_bitcast"
external build_trunc_or_bitcast : llvalue -> lltype -> string -> llbuilder ->
                                  llvalue = "llvm_build_trunc_or_bitcast"
external build_pointercast : llvalue -> lltype -> string -> llbuilder -> llvalue
                           = "llvm_build_pointercast"
external build_intcast : llvalue -> lltype -> string -> llbuilder -> llvalue
                       = "llvm_build_intcast"
external build_fpcast : llvalue -> lltype -> string -> llbuilder -> llvalue
                      = "llvm_build_fpcast"

(*--... Comparisons ........................................................--*)
external build_icmp : Icmp.t -> llvalue -> llvalue -> string ->
                      llbuilder -> llvalue = "llvm_build_icmp"
external build_fcmp : Fcmp.t -> llvalue -> llvalue -> string ->
                      llbuilder -> llvalue = "llvm_build_fcmp"

(*--... Miscellaneous instructions .........................................--*)
external build_phi : (llvalue * llbasicblock) list -> string -> llbuilder ->
                     llvalue = "llvm_build_phi"
external build_call : llvalue -> llvalue array -> string -> llbuilder -> llvalue
                    = "llvm_build_call"
external build_select : llvalue -> llvalue -> llvalue -> string -> llbuilder ->
                        llvalue = "llvm_build_select"
external build_va_arg : llvalue -> lltype -> string -> llbuilder -> llvalue
                      = "llvm_build_va_arg"
external build_extractelement : llvalue -> llvalue -> string -> llbuilder ->
                                llvalue = "llvm_build_extractelement"
external build_insertelement : llvalue -> llvalue -> llvalue -> string ->
                               llbuilder -> llvalue = "llvm_build_insertelement"
external build_shufflevector : llvalue -> llvalue -> llvalue -> string ->
                               llbuilder -> llvalue = "llvm_build_shufflevector"
external build_extractvalue : llvalue -> int -> string -> llbuilder -> llvalue
                            = "llvm_build_extractvalue"
external build_insertvalue : llvalue -> llvalue -> int -> string -> llbuilder ->
                             llvalue = "llvm_build_insertvalue"

external build_is_null : llvalue -> string -> llbuilder -> llvalue
                       = "llvm_build_is_null"
external build_is_not_null : llvalue -> string -> llbuilder -> llvalue
                           = "llvm_build_is_not_null"
external build_ptrdiff : llvalue -> llvalue -> string -> llbuilder -> llvalue
                       = "llvm_build_ptrdiff"

(*===-- Module providers --------------------------------------------------===*)

module ModuleProvider = struct
  external create : llmodule -> llmoduleprovider
                  = "LLVMCreateModuleProviderForExistingModule"
  external dispose : llmoduleprovider -> unit = "llvm_dispose_module_provider"
end


(*===-- Memory buffers ----------------------------------------------------===*)

module MemoryBuffer = struct
  external of_file : string -> llmemorybuffer = "llvm_memorybuffer_of_file"
  external of_stdin : unit -> llmemorybuffer = "llvm_memorybuffer_of_stdin"
  external dispose : llmemorybuffer -> unit = "llvm_memorybuffer_dispose"
end


(*===-- Pass Manager ------------------------------------------------------===*)

module PassManager = struct
  type 'a t
  type any = [ `Module | `Function ]
  external create : unit -> [ `Module ] t = "llvm_passmanager_create"
  external create_function : llmoduleprovider -> [ `Function ] t
                           = "LLVMCreateFunctionPassManager"
  external run_module : llmodule -> [ `Module ] t -> bool
                      = "llvm_passmanager_run_module"
  external initialize : [ `Function ] t -> bool = "llvm_passmanager_initialize"
  external run_function : llvalue -> [ `Function ] t -> bool
                        = "llvm_passmanager_run_function"
  external finalize : [ `Function ] t -> bool = "llvm_passmanager_finalize"
  external dispose : [< any ] t -> unit = "llvm_passmanager_dispose"
end


(*===-- Non-Externs -------------------------------------------------------===*)
(* These functions are built using the externals, so must be declared late.   *)

let concat2 sep arr =
  let s = ref "" in
  if 0 < Array.length arr then begin
    s := !s ^ arr.(0);
    for i = 1 to (Array.length arr) - 1 do
      s := !s ^ sep ^ arr.(i)
    done
  end;
  !s

let rec string_of_lltype ty =
  (* FIXME: stop infinite recursion! :) *)
  match classify_type ty with
    TypeKind.Integer -> "i" ^ string_of_int (integer_bitwidth ty)
  | TypeKind.Pointer -> (string_of_lltype (element_type ty)) ^ "*"
  | TypeKind.Struct ->
      let s = "{ " ^ (concat2 ", " (
                Array.map string_of_lltype (struct_element_types ty)
              )) ^ " }" in
      if is_packed ty
        then "<" ^ s ^ ">"
        else s
  | TypeKind.Union -> "union { " ^ (concat2 ", " (
                        Array.map string_of_lltype (union_element_types ty)
                      )) ^ " }"
  | TypeKind.Array -> "["   ^ (string_of_int (array_length ty)) ^
                      " x " ^ (string_of_lltype (element_type ty)) ^ "]"
  | TypeKind.Vector -> "<"   ^ (string_of_int (vector_size ty)) ^
                       " x " ^ (string_of_lltype (element_type ty)) ^ ">"
  | TypeKind.Opaque -> "opaque"
  | TypeKind.Function -> string_of_lltype (return_type ty) ^
                         " (" ^ (concat2 ", " (
                           Array.map string_of_lltype (param_types ty)
                         )) ^ ")"
  | TypeKind.Label -> "label"
  | TypeKind.Ppc_fp128 -> "ppc_fp128"
  | TypeKind.Fp128 -> "fp128"
  | TypeKind.X86fp80 -> "x86_fp80"
  | TypeKind.Double -> "double"
  | TypeKind.Float -> "float"
  | TypeKind.Void -> "void"
  | TypeKind.Metadata -> "metadata"
