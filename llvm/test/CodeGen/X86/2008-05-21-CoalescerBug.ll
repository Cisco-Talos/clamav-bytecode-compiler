; RUN: llc < %s -march=x86 -O0 -fast-isel=false | grep mov | count 5
; PR2343

	%llvm.dbg.anchor.type = type { i32, i32 }
	%struct.CUMULATIVE_ARGS = type { i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32 }
	%struct.VEC_basic_block_base = type { i32, i32, [1 x %struct.basic_block_def*] }
	%struct.VEC_basic_block_gc = type { %struct.VEC_basic_block_base }
	%struct.VEC_edge_base = type { i32, i32, [1 x %struct.edge_def*] }
	%struct.VEC_edge_gc = type { %struct.VEC_edge_base }
	%struct.VEC_rtx_base = type { i32, i32, [1 x %struct.rtx_def*] }
	%struct.VEC_rtx_gc = type { %struct.VEC_rtx_base }
	%struct.VEC_temp_slot_p_base = type { i32, i32, [1 x %struct.temp_slot*] }
	%struct.VEC_temp_slot_p_gc = type { %struct.VEC_temp_slot_p_base }
	%struct.VEC_tree_base = type { i32, i32, [1 x %struct.tree_node*] }
	%struct.VEC_tree_gc = type { %struct.VEC_tree_base }
	%struct.__sbuf = type { i8*, i32 }
	%struct._obstack_chunk = type { i8*, %struct._obstack_chunk*, [4 x i8] }
	%struct.basic_block_def = type { %struct.tree_node*, %struct.VEC_edge_gc*, %struct.VEC_edge_gc*, i8*, %struct.loop*, [2 x %struct.et_node*], %struct.basic_block_def*, %struct.basic_block_def*, %struct.basic_block_il_dependent, %struct.tree_node*, %struct.edge_prediction*, i64, i32, i32, i32, i32 }
	%struct.basic_block_il_dependent = type { %struct.rtl_bb_info* }
	%struct.bitmap_element_def = type { %struct.bitmap_element_def*, %struct.bitmap_element_def*, i32, [4 x i32] }
	%struct.bitmap_head_def = type { %struct.bitmap_element_def*, %struct.bitmap_element_def*, i32, %struct.bitmap_obstack* }
	%struct.bitmap_obstack = type { %struct.bitmap_element_def*, %struct.bitmap_head_def*, %struct.obstack }
	%struct.block_symbol = type { [3 x %struct.cfg_stats_d], %struct.object_block*, i64 }
	%struct.cfg_stats_d = type { i32 }
	%struct.control_flow_graph = type { %struct.basic_block_def*, %struct.basic_block_def*, %struct.VEC_basic_block_gc*, i32, i32, i32, %struct.VEC_basic_block_gc*, i32 }
	%struct.def_optype_d = type { %struct.def_optype_d*, %struct.tree_node** }
	%struct.edge_def = type { %struct.basic_block_def*, %struct.basic_block_def*, %struct.edge_def_insns, i8*, %struct.__sbuf*, i32, i32, i64, i32 }
	%struct.edge_def_insns = type { %struct.rtx_def* }
	%struct.edge_prediction = type { %struct.edge_prediction*, %struct.edge_def*, i32, i32 }
	%struct.eh_status = type opaque
	%struct.emit_status = type { i32, i32, %struct.rtx_def*, %struct.rtx_def*, %struct.sequence_stack*, i32, %struct.__sbuf, i32, i8*, %struct.rtx_def** }
	%struct.et_node = type opaque
	%struct.expr_status = type { i32, i32, i32, %struct.rtx_def*, %struct.rtx_def*, %struct.rtx_def* }
	%struct.function = type { %struct.eh_status*, %struct.expr_status*, %struct.emit_status*, %struct.varasm_status*, %struct.control_flow_graph*, %struct.tree_node*, %struct.function*, i32, i32, i32, i32, %struct.rtx_def*, %struct.CUMULATIVE_ARGS, %struct.rtx_def*, %struct.rtx_def*, %struct.initial_value_struct*, %struct.rtx_def*, %struct.rtx_def*, %struct.rtx_def*, %struct.rtx_def*, %struct.rtx_def*, %struct.rtx_def*, i8, i32, i64, %struct.tree_node*, %struct.tree_node*, %struct.rtx_def*, %struct.VEC_temp_slot_p_gc*, %struct.temp_slot*, %struct.var_refs_queue*, i32, i32, i32, i32, %struct.machine_function*, i32, i32, %struct.language_function*, %struct.htab*, %struct.rtx_def*, i32, i32, i32, %struct.__sbuf, %struct.VEC_tree_gc*, %struct.tree_node*, i8*, i8*, i8*, i8*, i8*, %struct.tree_node*, i8, i8, i8, i8, i8, i8 }
	%struct.htab = type { i32 (i8*)*, i32 (i8*, i8*)*, void (i8*)*, i8**, i32, i32, i32, i32, i32, i8* (i32, i32)*, void (i8*)*, i8*, i8* (i8*, i32, i32)*, void (i8*, i8*)*, i32 }
	%struct.initial_value_struct = type opaque
	%struct.lang_decl = type opaque
	%struct.language_function = type opaque
	%struct.loop = type { i32, %struct.basic_block_def*, %struct.basic_block_def*, %llvm.dbg.anchor.type, i32, i32, i32, i32, %struct.loop**, i32, %struct.loop*, %struct.loop*, %struct.loop*, %struct.loop*, i8*, %struct.tree_node*, %struct.tree_node*, %struct.nb_iter_bound*, %struct.edge_def*, i32 }
	%struct.machine_function = type opaque
	%struct.maydef_optype_d = type { %struct.maydef_optype_d*, %struct.tree_node*, %struct.tree_node*, %struct.ssa_use_operand_d }
	%struct.nb_iter_bound = type { %struct.tree_node*, %struct.tree_node*, %struct.nb_iter_bound* }
	%struct.object_block = type { %struct.section*, i32, i64, %struct.VEC_rtx_gc*, %struct.VEC_rtx_gc* }
	%struct.obstack = type { i32, %struct._obstack_chunk*, i8*, i8*, i8*, i32, i32, %struct._obstack_chunk* (i8*, i32)*, void (i8*, %struct._obstack_chunk*)*, i8*, i8 }
	%struct.rtl_bb_info = type { %struct.rtx_def*, %struct.rtx_def*, %struct.bitmap_head_def*, %struct.bitmap_head_def*, %struct.rtx_def*, %struct.rtx_def*, i32 }
	%struct.rtx_def = type { i16, i8, i8, %struct.u }
	%struct.section = type { %struct.unnamed_section }
	%struct.sequence_stack = type { %struct.rtx_def*, %struct.rtx_def*, %struct.sequence_stack* }
	%struct.ssa_use_operand_d = type { %struct.ssa_use_operand_d*, %struct.ssa_use_operand_d*, %struct.tree_node*, %struct.tree_node** }
	%struct.stmt_ann_d = type { %struct.tree_ann_common_d, i8, %struct.basic_block_def*, %struct.stmt_operands_d, %struct.bitmap_head_def*, i32, i8* }
	%struct.stmt_operands_d = type { %struct.def_optype_d*, %struct.use_optype_d*, %struct.maydef_optype_d*, %struct.vuse_optype_d*, %struct.maydef_optype_d* }
	%struct.temp_slot = type opaque
	%struct.tree_ann_common_d = type { i32, i8*, %struct.tree_node* }
	%struct.tree_ann_d = type { %struct.stmt_ann_d }
	%struct.tree_common = type { %struct.tree_node*, %struct.tree_node*, %struct.tree_ann_d*, i8, i8, i8, i8, i8 }
	%struct.tree_decl_common = type { %struct.tree_decl_minimal, %struct.tree_node*, i8, i8, i8, i8, i8, i32, %struct.tree_decl_u1, %struct.tree_node*, %struct.tree_node*, %struct.tree_node*, %struct.tree_node*, i64, %struct.lang_decl* }
	%struct.tree_decl_minimal = type { %struct.tree_common, %struct.__sbuf, i32, %struct.tree_node*, %struct.tree_node* }
	%struct.tree_decl_non_common = type { %struct.tree_decl_with_vis, %struct.tree_node*, %struct.tree_node*, %struct.tree_node*, %struct.tree_node* }
	%struct.tree_decl_u1 = type { i64 }
	%struct.tree_decl_with_rtl = type { %struct.tree_decl_common, %struct.rtx_def*, i32 }
	%struct.tree_decl_with_vis = type { %struct.tree_decl_with_rtl, %struct.tree_node*, %struct.tree_node*, i8, i8, i8 }
	%struct.tree_function_decl = type { %struct.tree_decl_non_common, i8, i8, i64, %struct.function* }
	%struct.tree_node = type { %struct.tree_function_decl }
	%struct.u = type { %struct.block_symbol }
	%struct.unnamed_section = type { %struct.cfg_stats_d, void (i8*)*, i8*, %struct.section* }
	%struct.use_optype_d = type { %struct.use_optype_d*, %struct.ssa_use_operand_d }
	%struct.var_refs_queue = type { %struct.rtx_def*, i32, i32, %struct.var_refs_queue* }
	%struct.varasm_status = type opaque
	%struct.vuse_optype_d = type { %struct.vuse_optype_d*, %struct.tree_node*, %struct.ssa_use_operand_d }
@llvm.used = appending global [1 x i8*] [ i8* bitcast (%struct.edge_def* (%struct.edge_def*, %struct.basic_block_def*)* @tree_redirect_edge_and_branch to i8*) ], section "llvm.metadata"		; <[1 x i8*]*> [#uses=0]

define %struct.edge_def* @tree_redirect_edge_and_branch(%struct.edge_def* %e1, %struct.basic_block_def* %dest2) nounwind  {
entry:
	br label %bb497

bb483:		; preds = %bb497
	%tmp496 = load %struct.tree_node** null, align 4		; <%struct.tree_node*> [#uses=1]
	br label %bb497

bb497:		; preds = %bb483, %entry
	%cases.0 = phi %struct.tree_node* [ %tmp496, %bb483 ], [ null, %entry ]		; <%struct.tree_node*> [#uses=1]
	%last.0 = phi %struct.tree_node* [ %cases.0, %bb483 ], [ undef, %entry ]		; <%struct.tree_node*> [#uses=1]
	%foo = phi i1 [ 0, %bb483 ], [ 1, %entry ]
	br i1 %foo, label %bb483, label %bb502

bb502:		; preds = %bb497
	br i1 %foo, label %bb507, label %bb841

bb507:		; preds = %bb502
	%tmp517 = getelementptr %struct.tree_node* %last.0, i32 0, i32 0		; <%struct.tree_function_decl*> [#uses=1]
	%tmp517518 = bitcast %struct.tree_function_decl* %tmp517 to %struct.tree_common*		; <%struct.tree_common*> [#uses=1]
	%tmp519 = getelementptr %struct.tree_common* %tmp517518, i32 0, i32 0		; <%struct.tree_node**> [#uses=1]
	store %struct.tree_node* null, %struct.tree_node** %tmp519, align 4
	br label %bb841

bb841:		; preds = %bb507, %bb502
	unreachable
}
