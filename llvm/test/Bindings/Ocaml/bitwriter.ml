(* RUN: %ocamlopt -warn-error A llvm.cmxa llvm_bitwriter.cmxa %s -o %t
 * RUN: ./%t %t.bc
 * RUN: llvm-dis < %t.bc | grep caml_int_ty
 *)

(* Note that this takes a moment to link, so it's best to keep the number of
   individual tests low. *)

let context = Llvm.global_context ()

let test x = if not x then exit 1 else ()

let _ =
  let m = Llvm.create_module context "ocaml_test_module" in
  
  ignore (Llvm.define_type_name "caml_int_ty" (Llvm.i32_type context) m);
  
  test (Llvm_bitwriter.write_bitcode_file m Sys.argv.(1))
