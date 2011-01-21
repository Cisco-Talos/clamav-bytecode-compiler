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

module ValueType = struct
  type t = llvalue;
  value compare (a:t) (b:t) = Pervasives.compare a b;
end;

module ValueMap = Map.Make(ValueType);

type value_type =
  [ AllocaLS of int64 (* only used for load-stores, can be transformed into SSA var *)
  | AllocaAddressTaken of int64 (* should be real alloca *)
  | BBLocal of int64 (* local to a BB *)
  | Void (* instructions that don't return anything *)
  ];

type alloca_type =
  [ RealAlloca of int64
  | LSAlloca of int64 and int];

type t = {
  function_ids: Hashtbl.t llvalue (Linksection.kind * int);
  maxid: int;
  f: Encode.bytecode_file;
  value_map: mutable ValueMap.t value_type;
  alloca_map: mutable ValueMap.t alloca_type;
};

value create f maxid ids len = do {
  Encode.add_bits_vbrlow f len;
  {
    function_ids = ids;
    maxid = maxid;
    f = f;
    value_map = ValueMap.empty;
    alloca_map = ValueMap.empty;
  };
};

type bcopcode =
  [ OpSkip (* don't emit *)
  (* arithmetic *)
  | OpAdd
  | OpSub
  | OpMul
  | OpUDiv
  | OpSDiv
  | OpURem
  | OpSRem
  (* logic *)
  | OpShl
  | OpLShr
  | OpAShr
  | OpAnd
  | OpOr
  | OpXor
  (* ext/trunc *)
  | OpTrunc
  | OpSExt
  | OpZExt
  (* control flow *)
  | OpBranch
  | OpJump
  | OpSwitch
  | OpRetN
  | OpRetVoid
  (* compare *)
  | OpICmpEQ
  | OpICmpNE
  | OpICmpUGT
  | OpICmpUGE
  | OpICmpULT
  | OpICmpULE
  | OpICmpSGT
  | OpICmpSGE
  | OpICmpSLE
  | OpICmpSLT
  | OpSelect
  (* calls *)
  | OpCallInternal
  | OpCallAPI
  (* mem *)
  | OpCopy
  | OpGEPN
  | OpStore
  | OpLoad
  | OpMemset
  | OpMemcpy
  | OpMemmove
  (* misc *)
  | OpAbort
  | OpBSwap16
  | OpBSwap32
  | OpBSwap64
  | OpPtrToInt64
  ];

value map_binop instr = match instr with
 [ Opcode.Add -> OpAdd
 | Opcode.Sub -> OpSub
 | Opcode.Mul -> OpMul
 | Opcode.UDiv -> OpUDiv
 | Opcode.SDiv -> OpSDiv
 | Opcode.URem -> OpURem
 | Opcode.SRem -> OpSRem
 | Opcode.Shl -> OpShl
 | Opcode.LShr -> OpLShr
 | Opcode.AShr -> OpAShr
 | Opcode.And -> OpAnd
 | Opcode.Or -> OpOr
 | Opcode.Xor -> OpXor
 | _ -> assert False
 ];

value int_of_bcopcode (op:bcopcode) = Int64.of_int (Hashtbl.hash op);

type operand_kind = [ FixedOps of int | VariableOps ];

value opcode_operands op = match op with
 [ OpSkip | OpRetVoid ->
   FixedOps 0

 | OpTrunc | OpSExt | OpZExt | OpStore | OpLoad | OpCopy |
   OpJump | OpBSwap16 | OpBSwap32 | OpBSwap64 | OpPtrToInt64 ->
     FixedOps 1

 | OpAdd | OpSub | OpMul | OpUDiv | OpSDiv | OpURem | OpSRem |
   OpShl | OpLShr | OpAShr | OpAnd | OpOr | OpXor |
   OpICmpEQ | OpICmpNE | OpICmpUGT | OpICmpUGE | OpICmpULT |
   OpICmpULE | OpICmpSGT | OpICmpSGE | OpICmpSLE | OpICmpSLT ->
     FixedOps 2

 | OpBranch | OpSelect | OpMemset | OpMemcpy | OpMemmove |
   OpAbort ->
     FixedOps 3

 | OpCallInternal | OpCallAPI | OpRetN | OpSwitch | OpGEPN ->
     VariableOps
 ];

type bcdest =
  [ DstBBValue of bcinstr (* store result to a BB local value *)
  | DstPtrAlloca of llvalue and int (* store result to alloca + offset *)
  | DstPtrOff of bcinstr and int (* store result to <ptr>+offset, where ptr is a local variable *)
  | DstPtrArg of llvalue and int (* store result to <argvalue>+offset *)
  | DstGlobal of llvalue and int (* store result to global + offset *)
  ]

(* globals are really instance/thread-local, the mem is allocated on bc_execute
 * and is not shared *)

and bcsrc =
  [ SrcArgValue of llvalue
  | SrcBBValue of bcinstr
  | SrcAddressOf of llvalue and int
  | SrcAllocaLoad of llvalue and int
  | SrcGlobalLoad of llvalue and int
  | SrcImmediate of llvalue
  | SrcBBId of int
  | SrcFuncId of int
  ]

(* interpreter: ArgValue: 0,1,2...., then BBValue..., on new BB the buffer is
 * expanded/shrunk, but args stay at bottom *)

and bcinstr = {
  dest: bcdest;
  opcode: bcopcode;
  operands: array bcsrc;
};

value classify_allocas s v =
  let rec check_only_loadstore u = match instr_opcode u with
  [ Opcode.Load -> True
  | Opcode.BitCast -> check_only_loadstore (operand u 0)
  | Opcode.Store -> (operand u 0) <> v
  (* if it was used for source op of store then its address is taken,
   * and is no longer a simple SSA value *)
  | _ -> False
  ] in
  let check_alloca cond use =
    if cond then check_only_loadstore (user use)
    else False in
  if instr_opcode v <> Opcode.Alloca then ()
  else do {
    let bytes = Layout.typesize (type_of v) in
    let kind =
      if fold_left_uses check_alloca True v then
        AllocaLS bytes
      else
        AllocaAddressTaken bytes in
    s.value_map := ValueMap.add v kind s.value_map;
  };

value classify_values s count v =
  let t = type_of v in
  let (kind, result, add) =
    if  classify_type t <> TypeKind.Void then
      let size = Layout.typesize t in
        if size > 8L then
          raise (NotSupported "Local variables larger than 64-bit" (Val v))
        else
          (BBLocal size, size, 1)
    else
      (Void, 0L, 0) in do {
        s.value_map := ValueMap.add v kind s.value_map;
        count + add;
      };

value finish s = do {
  (* emit empty function *)
  (* begin_function *)
  Encode.add_bits_vbrlow s.f 0;
  Encode.add_bits_vbrlow s.f 0;
  Encode.add_bits_vbrlow s.f 0;
  Encode.add_bits_vbrlow s.f 0;
  Encode.add_bits_vbrlow s.f 0;
  Encode.add_bits_vbrlow s.f 0;
  Encode.add_bits_vbr s.f 0_L;
  Encode.add_bits_vbr s.f 0_L;
  (* end_function *)
  Encode.add_bits_vbrlow s.f 0;
};

value build_alloca_map map =
  let all_als = Queue.create () in
  (* classify alloca by max align *)
  let allocate_lsonly (map,off,cnt) (a,v)=
    match v with
    [ AllocaLS n -> do {
      Queue.add n all_als;
      (ValueMap.add a (LSAlloca off cnt) map, Int64.add off n, cnt+1)
     }
    | AllocaAddressTaken n ->
      (map, off, cnt)
    | BBLocal _ | Void -> assert False
    ] in

  let allocate_real (map,off) (a,v)=
    match v with
    [ AllocaLS n ->
      (map, off)
    | AllocaAddressTaken n ->
      (ValueMap.add a (RealAlloca off) map, Int64.add off n)
    | BBLocal _ | Void -> assert False
    ] in

  let a1 = Queue.create ()
  and a4 = Queue.create ()
  and a8 = Queue.create () in
  let classify_alloca a v =
    match v with
    [ (AllocaLS n | AllocaAddressTaken n) when Int64.rem n 8_L = 0_L ->
      Queue.add (a,v) a8
    | (AllocaLS n | AllocaAddressTaken n) when Int64.rem n 4_L = 0_L ->
      Queue.add (a,v) a4
    | (AllocaLS n | AllocaAddressTaken n) ->
      Queue.add (a,v) a1
    | BBLocal _ | Void -> ()
    ] in

  do {
    ValueMap.iter classify_alloca map;
    let o1 = Queue.fold allocate_real (ValueMap.empty, 0_L) a8 in
    let o2 = Queue.fold allocate_real o1 a4 in
    let (m3,end_alloca) = Queue.fold allocate_real o2 a1 in
    let o4 = Queue.fold allocate_lsonly (m3,end_alloca, 0) a8 in
    let o5 = Queue.fold allocate_lsonly o4 a4 in
    let (map,end_als,end_alscnt) = Queue.fold allocate_lsonly o5 a1 in

    let als_arr = Array.make (Queue.length all_als) 0 in do {
      assert (end_alscnt = (Array.length als_arr));
      Queue.fold (fun i n -> do { als_arr.(i) := Int64.to_int n; i+1};) 0 all_als;
      (map, end_alloca, end_als, als_arr);
    }
  };


value begin_function s func = do {
  (* count non-void instructions -> local variables in block;
   * reg2mem ensure that values are not live accross blocks,
   * and that we have no PHIs *)
  let analyze_instr count instr =
    if (classify_type (type_of instr)) <> TypeKind.Void then count+1
    else count in
  let analyze_block (prevn, prevmaxl) block =
    (prevn+1, max (fold_left_instrs analyze_instr 0 block) prevmaxl) in
  let (n, maxlocal) = fold_left_blocks analyze_block (0, 0) func in do {
    Encode.add_bits_vbrlow s.f n;
    Encode.add_bits_vbrlow s.f maxlocal;
    (* count bytes from allocas that are only used for load/dest store, and don't
     * have its address taken for GEP/call/source part of store.
     * These are local vars to the function *)
    s.value_map := ValueMap.empty;
    iter_instrs (classify_allocas s) (entry_block func);
    let (map, alloca_bytes, lsbytes, alsarr) = build_alloca_map s.value_map in do {
      s.alloca_map := map;
      Encode.add_bits_vbrlow s.f (Int64.to_int alloca_bytes);
      Encode.add_bits_vbrlow s.f (Int64.to_int lsbytes);
      Encode.add_bits_vbrlow s.f (Array.length alsarr);
      Array.iter (Encode.add_bits_vbrlow s.f) alsarr;
    };

    let max_block themax block =
      let c = fold_left_instrs (classify_values s) 0 block in
      if c > themax then c else themax in
    let max_bb_local = fold_left_blocks max_block 0 func in
    Encode.add_bits_vbrlow s.f max_bb_local;

    let sum_alloca_bytes _ data (sum_ls, sum_at) =
      match data with
      [ AllocaLS b -> (Int64.add sum_ls b, sum_at)
      | AllocaAddressTaken b -> (sum_ls, Int64.add sum_at b)
      | BBLocal _ | Void -> (sum_ls, sum_at)] in
    let (bytes_ls, bytes_at) = ValueMap.fold sum_alloca_bytes s.value_map (0L,0L)
    in do {
      Encode.add_bits_vbr s.f bytes_ls;
      Encode.add_bits_vbr s.f bytes_at;
    };
  };
};

value end_function s f =
  Encode.add_bits_vbrlow s.f 0;

module InstHType = struct
  type t = bcinstr;
  value equal a b =
    let destok =
      if a.dest == b.dest then True
      else False in
    destok && (a.opcode == b.opcode) && (a.operands == b.operands);

  value hash = Hashtbl.hash;
end;

module InstHash = Hashtbl.Make(InstHType);

value emit_block s f block =
  let count = fold_left_instrs (fun c _ -> c+1) 0 block in
  let bb_values = Hashtbl.create (count*4/3) in
  let emitted_inst = InstHash.create (count*4/3) in
  let num_args = Array.length (params (block_parent block)) in

  let get_load_addr src off fallback =
    match classify_value src with
    [ ValueKind.Instruction -> do {
      assert ((instr_opcode src) = Opcode.Alloca);
      SrcAllocaLoad src off
      }
    | ValueKind.GlobalVariable -> SrcGlobalLoad src off
    | _ -> fallback ] in

  let optimize_operand op =
    match op with
    [ {opcode = OpLoad; operands = [| SrcAddressOf src off |]} ->
      get_load_addr src off (SrcBBValue op)
    | {opcode=OpSkip} -> raise Not_found
    |  _ as result -> SrcBBValue result
    ] in

  let get_operand op =
    try
      optimize_operand (Hashtbl.find bb_values op)
    with [Not_found ->
      match classify_value op with
      [ ValueKind.Argument -> SrcArgValue op

      | ValueKind.GlobalVariable ->
          SrcAddressOf op 0
      | ValueKind.Instruction -> do {
          assert ((instr_opcode op) = Opcode.Alloca);
          SrcAddressOf op 0;
        }

      | ValueKind.ConstantExpr ->
          (*TODO: eval constant expr and build an SrcAddressOf*)
          raise (NotSupportedYet "cexpr TODO" (Val op))

      | ValueKind.ConstantInt ->
          let n = integer_bitwidth (type_of op) in
          if n <= 64 then
            SrcImmediate op
          else
            raise (NotSupported "Larger than 64-bit integers" (Val op))
      | ValueKind.ConstantPointerNull ->
          SrcImmediate op

      | ValueKind.UndefValue ->
          raise (UndefError "Use of undefined value" (Val op))
      | ValueKind.GlobalAlias ->
          raise (NotSupportedYet "Global aliases" (Val op))
      | ValueKind.InlineAsm ->
          raise (NotSupported "Inline assembly" (Val op))
      | ValueKind.ConstantFP ->
          raise (NotSupported "Floating point constant" (Val op))
      | ValueKind.ConstantVector ->
          raise (NotSupported "Vector constants" (Val op))
      | ValueKind.ConstantArray | ValueKind.ConstantAggregateZero |
        ValueKind.ConstantStruct->
          raise (LogicError "array/aggregate SSA values" (Val op))
      | ValueKind.BlockAddress ->
          raise (NotSupported "goto" (Val op))
      | ValueKind.BasicBlock | ValueKind.MDNode | ValueKind.MDString |
        ValueKind.NullValue -> do {
          assert False
        }
      | ValueKind.Function ->
          raise (NotSupported "Function pointers" (Val op))
      ]
    ]

  and get_dst_operand dst =
    try
       let r = Hashtbl.find bb_values dst in
       match r with
       [ {opcode=OpSkip} -> raise Not_found
       | _ -> DstPtrOff r 0]
    with [Not_found ->
      match classify_value dst with
      [ ValueKind.Instruction -> do {
        assert ((instr_opcode dst) = Opcode.Alloca);
        DstPtrAlloca dst 0
       }
      | ValueKind.GlobalVariable -> DstGlobal dst 0
      | ValueKind.ConstantExpr -> (* TODO eval const  *)
          raise (NotSupportedYet "constexpr dst" (Val dst))
      | ValueKind.Argument ->
          DstPtrArg dst 0
      | _ -> assert False]
    ] in

  let build_result opcode operands =
    let rec result = {
      dest = DstBBValue result;
      opcode = opcode;
      operands = operands;
    } in
    result in

  let get_bt () =
    if Printexc.backtrace_status () then
      Some (Printexc.get_backtrace ())
    else
      None in

  let buildop opcode instr n = do {
    assert ((num_operands instr) = n);
    let operands = Array.init n (fun i -> get_operand (operand instr i)) in
    build_result opcode operands;
  } in

  let buildskip () =
    build_result OpSkip [||] in

  let rec map_function f =
    try
      match Hashtbl.find s.function_ids f with
      [ (Linksection.Imported, id) ->
        (OpCallAPI, id)
      | (Linksection.Internal | Linksection.Exported, id) ->
          (OpCallInternal, id)]
    with [Not_found ->
      if (constexpr_opcode f) = Opcode.BitCast then
        map_function (operand f 0)
      else if classify_value f = ValueKind.InlineAsm then
        raise (NotSupported "Inline assembly" (Val f))
      else
        assert False
    ] in

  let get_bbid block = do {
    assert (value_is_block block);
    let rec findpos pos b =
      match block_pred b with
      [ At_start _ -> pos
      | After other -> findpos (pos+1) other] in
    SrcBBId (findpos 0 (block_of_value block))
  } in

  let emit_instruction instr =
  try
    do {
    let bcinst = match instr_opcode instr with
    [ Opcode.Alloca ->
      buildskip ()
    | Opcode.Store -> do {
        assert ((num_operands instr) = 2);
        let src = operand instr 0;
        let dst = operand instr 1;
        {dest = get_dst_operand dst; opcode = OpStore;
        operands = [| get_operand src |]}
      }

    | Opcode.Load ->
        buildop OpLoad instr 1
    | Opcode.BitCast ->
        buildop OpCopy instr 1
    | Opcode.PtrToInt ->
        buildop OpPtrToInt64 instr 1
    | Opcode.SExt ->
        buildop OpSExt instr 1
    | Opcode.ZExt ->
        buildop OpZExt instr 1
    | Opcode.Trunc ->
        buildop OpTrunc instr 1

    | Opcode.Add | Opcode.Sub | Opcode.Mul | Opcode.UDiv | Opcode.SDiv |
      Opcode.URem | Opcode.SRem | Opcode.Shl | Opcode.LShr | Opcode.AShr |
      Opcode.And | Opcode.Or | Opcode.Xor as opc ->
        buildop (map_binop opc) instr 2

    | Opcode.Call -> let nop = num_operands instr in do {
        assert (nop >= 1);
        let f = operand instr (nop-1);
        if (Linksection.starts_with (value_name f) "llvm.dbg") then
          buildskip ()
        else do {
          let (op, funcid) = map_function f in
          let operands = Array.init nop (fun i ->
            if i = 0 then
              SrcFuncId funcid
            else
              get_operand (operand instr (i-1))) in
          build_result OpCallInternal operands;
        }
      }

    | Opcode.Ret -> do {
       if ((num_operands instr) = 0) then
         buildop OpRetVoid instr 0
       else
         buildop OpRetN instr (num_operands instr)
      }

    | Opcode.Select ->
        buildop OpSelect instr 3

    | Opcode.ICmp ->
        buildop (
        match instr_icmp_predicate instr with
        [ Some Icmp.Eq -> OpICmpEQ
        | Some Icmp.Ne -> OpICmpNE
        | Some Icmp.Ugt -> OpICmpUGT
        | Some Icmp.Uge -> OpICmpUGE
        | Some Icmp.Ult -> OpICmpULT
        | Some Icmp.Ule -> OpICmpULE
        | Some Icmp.Sgt -> OpICmpSGT
        | Some Icmp.Sge -> OpICmpSGE
        | Some Icmp.Slt -> OpICmpSLT
        | Some Icmp.Sle -> OpICmpSLE
        | None -> assert False
        ]) instr 2

    | Opcode.GetElementPtr ->
        buildop OpGEPN instr (num_operands instr)

    | Opcode.Switch -> let n = (num_operands instr) in do {
        (* cond, default_dest, bb1, value1, bb2, value2 ... *)
      assert (((n >= 2) && ((n mod 2) = 0)));
      let operands = Array.make n (SrcBBId 0) in do {
        operands.(0) := get_operand (operand instr 0);
        operands.(1) := get_bbid (operand instr 1);
        for i = 2 to n-1 do {
          let op = operand instr i in
          operands.(i) :=
            (if i mod n = 0 then get_bbid else get_operand) op;
        };
        build_result OpSwitch operands;
      };
    }

    | Opcode.Br ->
        match num_operands instr with
        [ 1 ->
          build_result OpJump [| get_bbid (operand instr 0) |]
        | 3 ->
          build_result OpBranch [|
            get_operand (operand instr 0);
            get_bbid (operand instr 1);
            get_bbid (operand instr 2)|]
        | _ -> assert False
        ]

    | Opcode.Unreachable ->
        let mapval v = match v with
        [ Some x -> const_int (i32_type context) x
        | None -> const_int (i32_type context) 0] in
        let loc = Debug.source_location instr s.f.Encode.name in
        (* TODO: include source loc here *)
        build_result OpAbort [|
          SrcFuncId 0;
          (SrcImmediate (mapval loc.Debug.lineno));
          (SrcImmediate (mapval loc.Debug.col))
        |]

    | Opcode.IndirectBr -> raise (NotSupported "goto" (Val instr))
    | Opcode.Invoke | Opcode.Unwind ->
        raise (NotSupported "try/catch/throw" (Val instr))
    | Opcode.FAdd | Opcode.FSub | Opcode.FMul | Opcode.FDiv | Opcode.FRem |
      Opcode.FPToUI | Opcode.FPToSI | Opcode.UIToFP | Opcode.SIToFP |
      Opcode.FPTrunc | Opcode.FPExt | Opcode.FCmp ->
        raise (NotSupported "Floating point operations" (Val instr))
    | Opcode.IntToPtr ->
        raise (NotSupported "building pointers from integers" (Val instr))
    | Opcode.PHI ->
        assert False (* reg2mem should have eliminated it *)
    | Opcode.UserOp1 | Opcode.UserOp2 | Opcode.Invalid ->
        assert False (* nothing emits these *)
    | Opcode.VAArg ->
        raise (NotSupported "internal vararg functions" (Val instr))
    | Opcode.ExtractElement | Opcode.InsertElement | Opcode.ShuffleVector |
      Opcode.ExtractValue | Opcode.InsertValue ->
        raise (NotSupported "vector operations" (Val instr))
    ];

    Hashtbl.add bb_values instr bcinst
  }
  with
  [ (NotSupported _ as e) | (NotSupportedYet _ as e) | (LogicError _ as e)  | (UndefError _ as e) -> raise e
  |  e ->
    raise (Internal "emit_instruction" (get_bt ()) (Val instr) e)] in

  let arg_pos a =
    let rec findpos pos param =
      match param_pred param with
      [ At_start _ -> pos
      | After other -> findpos (pos+1) other] in
    findpos 0 a in

  let emit_alloca_ref llval off =
    match ValueMap.find llval s.alloca_map with
    [ LSAlloca _ id -> do {
      Encode.add_bits s.f 0_L 1;
      Encode.add_bits_vbrlow s.f id;
      assert (off = 0);
      }
    | RealAlloca aoff -> do {
      Encode.add_bits s.f 1_L 1;
      Encode.add_bits_vbrlow s.f ((Int64.to_int aoff) + off);
      }
    ] in

  let emit_llval_addr llval off =
    (*TODO*) () in

  let emit_global llval off = do {
    ()
(*    .... global_map ...
    Encode.add_bits_vbrlow global_id;
    Encode.add_bits_vbroff off;*)
  } in

  let emit_operand op =
    let srckind = match op with
    [ SrcImmediate _ -> 0_L
    | SrcArgValue _  | SrcBBValue _ -> 1_L
    | SrcAllocaLoad _ | SrcGlobalLoad _ -> 2_L
    | SrcAddressOf _ -> 3_L
    | SrcFuncId _ | SrcBBId _-> 0_L (* these are fixed-pos params, so don't
    really need an id *)
    ] in do {
      Encode.add_bits s.f srckind 2;
      match op with
      [ SrcArgValue llval ->
        Encode.add_bits_vbrlow s.f (arg_pos llval)
      | SrcBBValue binst ->
        let bbid = InstHash.find emitted_inst binst in
        Encode.add_bits_vbrlow s.f bbid
      | SrcAddressOf llval off -> do {
          emit_llval_addr llval off;
        }
      | SrcAllocaLoad llval off ->
          emit_alloca_ref llval off
      | SrcGlobalLoad llval off ->
          emit_global llval off
      | SrcImmediate llconst -> do {
          if is_null llconst then
            Encode.add_bits_vbr s.f 0_L
          else
            Encode.add_bits_vbr s.f (Layout.get_const_value llconst)
        }
      | SrcFuncId id | SrcBBId id ->
          Encode.add_bits_vbrlow s.f id
      ]
    } in

  let emit_destination inst = do {
    Encode.add_bits s.f (
      match inst.dest with
      [ DstBBValue _ -> 0_L
      | DstPtrAlloca _ _ -> 1_L
      | DstPtrOff _ _ | DstPtrArg _ _ -> 2_L
      | DstGlobal _ _ -> 3_L
      ]) 2;
    match inst.dest with
    [ DstBBValue i ->
      if i == inst then
        Encode.add_bits_vbroff s.f 0
      else
        Encode.add_bits_vbroff s.f (InstHash.find emitted_inst i)
    | DstPtrAlloca llval off ->
        emit_alloca_ref llval off
    | DstPtrOff llval off -> do {
        let bbid = num_args + (InstHash.find emitted_inst llval) in
        Encode.add_bits_vbrlow s.f bbid;
        Encode.add_bits_vbroff s.f off;
      }
    | DstPtrArg llval off -> do {
         let p = arg_pos llval;
         assert (p < num_args);
         Encode.add_bits_vbrlow s.f p;
         Encode.add_bits_vbroff s.f off;
      }
    | DstGlobal llval off -> emit_global llval off
    ]
  } in

  let real_emit_instruction i inst =
  try
    let bcinst = Hashtbl.find bb_values inst in
      if (bcinst.opcode <> OpSkip) then do {
        Encode.add_bits s.f (int_of_bcopcode bcinst.opcode) 8;
        emit_destination bcinst;
        let sizecode = match Layout.typesize_bits (type_of inst) with
        [ 0_L -> 0_L
        | 1_L -> 1_L
        | 8_L -> 2_L
        | 16_L -> 3_L
        | 32_L -> 4_L
        | 64_L -> 5_L
        | _ -> raise (NotSupportedYet "arbitrary sized integers" (Val inst))];
        Encode.add_bits s.f sizecode 3;

        let n = Array.length bcinst.operands in
        match opcode_operands bcinst.opcode with
        [ FixedOps exp -> do {
          assert (n = exp);
          }
        | VariableOps -> do {
          assert (n < 255);
          Encode.add_bits s.f (Int64.of_int n) 8;(* at most 255 operands *)
        }
        ];
        Array.iter emit_operand bcinst.operands;
        InstHash.add emitted_inst bcinst i;
        i+1;
      } else i
  with [e -> do {
    raise (Internal "real_emit_instruction" (get_bt ()) (Val inst) e)
  }
  ] in

  do {
    Encode.add_bits_vbrlow s.f count;
    iter_instrs emit_instruction block;
    (*TODO: forward stores *)
    (*TODO: eliminate unused instr (due to load/store fwding *)
    (*TODO: create alloca map *)
    fold_left_instrs real_emit_instruction 0 block;
    ()
    (*end_block code f block;*)
  };

(* vim: set sw=2: *)
