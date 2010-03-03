(* RUN: %ocamlopt -warn-error A llvm.cmxa llvm_scalar_opts.cmxa llvm_target.cmxa %s -o %t
 *)

(* Note: It takes several seconds for ocamlopt to link an executable with
         libLLVMCore.a, so it's better to write a big test than a bunch of
         little ones. *)

open Llvm
open Llvm_scalar_opts
open Llvm_target

let context = global_context ()
let void_type = Llvm.void_type context

(* Tiny unit test framework - really just to help find which line is busted *)
let suite name f =
  prerr_endline (name ^ ":");
  f ()


(*===-- Fixture -----------------------------------------------------------===*)

let filename = Sys.argv.(1)
let m = create_module context filename


(*===-- Transforms --------------------------------------------------------===*)

let test_transforms () =
  let (++) x f = ignore (f x); x in

  let fty = function_type void_type [| |] in
  let fn = define_function "fn" fty m in
  ignore (build_ret_void (builder_at_end context (entry_block fn)));
  
  let td = TargetData.create (target_triple m) in
  
  ignore (PassManager.create_function m
           ++ TargetData.add td
           ++ add_constant_propagation
					 ++ add_sccp
           ++ add_dead_store_elimination
           ++ add_aggressive_dce
           ++ add_scalar_repl_aggregation
           ++ add_ind_var_simplification
           ++ add_instruction_combination
           ++ add_licm
           ++ add_loop_unswitch
           ++ add_loop_unroll
           ++ add_loop_rotation
           ++ add_loop_index_split
           ++ add_memory_to_register_promotion
           ++ add_memory_to_register_demotion
           ++ add_reassociation
           ++ add_jump_threading
           ++ add_cfg_simplification
           ++ add_tail_call_elimination
           ++ add_gvn
           ++ add_memcpy_opt
           ++ add_loop_deletion
           ++ add_lib_call_simplification
           ++ PassManager.initialize
           ++ PassManager.run_function fn
           ++ PassManager.finalize
           ++ PassManager.dispose);
  
  TargetData.dispose td


(*===-- Driver ------------------------------------------------------------===*)

let _ =
  suite "transforms" test_transforms;
  dispose_module m
