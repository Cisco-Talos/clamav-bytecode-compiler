(* Copyright (c) 2010 Sourcefire, Inc. All rights reserved.
 * Author: Török Edvin
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *   * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *)
(* TODO: copyright header *)
open Re2internal;;
(* TODO: use records here? *)

type graph_prog_inst = (* graph explicit transitions *)
    [ `Memchr of (char * graph_prog_inst Lazy.t * graph_prog_inst Lazy.t)
    | `If of (char * graph_prog_inst Lazy.t * graph_prog_inst Lazy.t)
    | `Switch of (char array * graph_prog_inst Lazy.t) list
    | `Any of (graph_prog_inst Lazy.t)
    | `Match
    | `Fail
    | `SelfLoop
    ]
    (* children are lazy nodes because we may have loops in the graph, and
     * we either construct immutable nodes with lazy values, or make the nodes
     * mutable.
     * Either way we'll have to cache already computed nodes in a hashtable so
     * that we don't loop infinitely when there are loops in the graph *)

and tree_prog_inst = (* tree, missing transition is fallthrough to next inst *)
    [ `Loop of tree_prog_inst list
    | `LoopBreak
    | `Match
    | `Fail
    | `Nop
    | `Any of tree_prog_inst
    | `Memchr of (char * tree_prog_inst)
    | `If of (char * tree_prog_inst * tree_prog_inst)
    | `IgnoreChar of tree_prog_inst
    | `IfMask of (char * char * tree_prog_inst)
    | `Switch of (char array * tree_prog_inst) list
    | `StateJump of int
    | `InstList of tree_prog_inst list
    | `StateInsts of (int * tree_prog_inst list)
    ];;
(* TODO: use ocaml Graph module instead of hand written traversal *)
let get_selftransitions (trans : transitions) : (char array) =
    let arr = Array.make 256 true in
    let handle_transition (chars, _) =
        for i = 0 to (Array.length chars)-1 do
            arr.(int_of_char chars.(i)) <- false
        done
    in
    List.iter handle_transition trans;
    let result = ref [] in
    for i = 0 to 255 do
        if arr.(i) then
            result := List.rev_append !result [char_of_int i];
    done;
    Array.of_list !result;;

let rec compile_transitions trans on_false=
    let map_state (chars, lazy next) =
        (chars, compile_state next) in
    match trans with
    | (([| c |], lazy next) ::[]) ->
            `If (c, next, on_false)
    | (([| c1; c2 |], lazy next) :: []) ->
            `If (c1, next,
                `If(c2, next, on_false))
    | (([| c1 |], lazy next1) :: ([| c2 |], lazy next2) :: []) ->
            `If (c1, next1,
                `If(c2, next2, on_false))
    | _ -> `Switch (List.map map_state trans)
and track (chars : char array) f =
    print_string "invoking with: ";
    print chars;
    f
and cached_compile_state cache next =
    match Hashtbl.find_all cache next with
    | h :: [] -> h
    | [] -> let result = compile_state cache next in
                Hashtbl.add cache next result;
                result
    | _ -> raise (Failure "duplicate state in cache?")
and complementary a1 a2 =
    let arr = Array.make 256 0 in
    let full = Array.make 256 1 in
    for i = 0 to (Array.length a1) - 1 do
        arr.(int_of_char a1.(i)) <- 1
    done;
    for i = 0 to (Array.length a2) -1 do
        let j = int_of_char a2.(i) in
        arr.(j) <- arr.(j) + 1
    done;
    arr = full
and compile_state cache (s : state) : graph_prog_inst  =
    match s with
    | `DeadState -> `Fail
    | `FullMatchState -> `Match
    | `SelfLoopState [] ->
            (* selfloop, fails on EOF -> fail now *)
            `Fail
    | `SelfLoopState (([|c|], lazy next)  :: []) ->
        (* single char transitions to another state -> memchr *)
            `Memchr (c, lazy (cached_compile_state cache next), lazy `Fail)
    | `SelfLoopState transitions ->
            print transitions;
            (* emit code for the selfloop, and handle the rest as generic *)
            (let selfloop_trans = get_selftransitions transitions in
            let next = `GenericState transitions in
            let compiled_next = lazy (cached_compile_state cache next) in
            match selfloop_trans with
            | [|c|] -> `If (c, lazy `SelfLoop, compiled_next)
            | _ -> let default_case = ([||], compiled_next) in
                    `Switch ((selfloop_trans, lazy `SelfLoop) :: [default_case])
            )
    | `GenericState [] ->
            `Fail
    | `GenericState (([|c|], lazy next) :: []) ->
            (* transition on single char to next, fail otherwise *)
            `If (c, lazy (cached_compile_state cache next), lazy `Fail)
    | `GenericState (([|c|], lazy next1) :: (chars, lazy next2) :: [])
        when (complementary [|c|] chars) ->
            `If (c,
                lazy (cached_compile_state cache next1),
                lazy (cached_compile_state cache next2))
    | `GenericState ((chars, lazy next) :: []) when (Array.length chars) = 256 ->
            `Any (lazy (cached_compile_state cache next))
    | `GenericState ((chars, lazy next) :: ([] | (([||], lazy `DeadState) :: [])))
            when (Array.length chars) = 256 ->
            `Any (lazy (cached_compile_state cache next))
    | `GenericState transitions ->
            let map_state (chars, lazy state) =
                (chars, lazy (cached_compile_state cache state)) in
            `Switch (List.map map_state transitions);;

(* transform prog into a full state machine, without optimizations *)
type fsm_cache_t = {t: (graph_prog_inst, int) Hashtbl.t; mutable max: int; mutable all: tree_prog_inst list};;
let rec transform_prog_fsm fsm_cache (prog: graph_prog_inst) : tree_prog_inst =
    match Hashtbl.find_all fsm_cache.t prog with
    | h :: [] ->
            (match prog with
            | `Match -> `Match
            | `Fail -> `Fail
            | _ -> `StateJump h)
    | [] ->
        Hashtbl.add fsm_cache.t prog fsm_cache.max;
        fsm_cache.max <- fsm_cache.max + 1;
        let (result : tree_prog_inst) =
        match prog with
        | `Memchr (c, lazy found, lazy fail) ->
            (let t = transform_prog_fsm fsm_cache found in
            let f = transform_prog_fsm fsm_cache fail in
            `InstList (`Memchr (c, t) :: [f]))
        | `If (c, lazy ontrue, lazy onfalse) ->
            (let t = transform_prog_fsm fsm_cache ontrue in
            let f =  transform_prog_fsm fsm_cache onfalse in
            `If (c, t, f))
        | `Switch l ->
            (let map_state (c, lazy p) =
                let x= transform_prog_fsm fsm_cache p in
                (c, x) in
            let n = List.fold_left (+) 0 (List.map (fun x -> Array.length (fst
            x)) l) in
            print n;
            `Switch (List.map map_state l))
        | `Match -> `Match
        | `Fail -> `Fail
        | `SelfLoop -> `StateJump (fsm_cache.max-1)
        | `Any (lazy `Match) -> `Match
        | `Any (lazy `Fail) -> `Fail
        | `Any (lazy n) -> `Any (transform_prog_fsm fsm_cache n)
        in
        fsm_cache.all <- List.append fsm_cache.all [result];
        result
    | _ -> raise (Failure "duplicate key in hash");;

let rec explore_prog cache level prog : unit=
    if (Hashtbl.mem cache prog) then
        print_string "cached\n"
    else begin
    Hashtbl.add cache prog true;
    print_string (String.make level ' ');
    match prog with
    | `Memchr (c, lazy s1, lazy s2) ->
            (print_string "memchr ";
            print_char c;
            print_string "; true branch:\n";
            explore_prog cache (level+1) s1;
            print_string (String.make level ' ');
            print_string "false branch:\n";
            explore_prog cache (level+1) s2)
    | `If (c, lazy s1, lazy s2) ->
            (print_string "if ";
            print_char c;
            print_string "; true branch:\n";
            explore_prog cache (level+1) s1;
            print_string (String.make level ' ');
            print_string "false branch:\n";
            explore_prog cache (level+1) s2)
    | `Switch (l : (char array * graph_prog_inst Lazy.t) list) ->
        (let explore_case (_, lazy s) =
            explore_prog cache (level+1) s in
        print_string "switch ";
        print_int (List.length l);
        print_string "\n";
        List.iter explore_case l)
    | _ -> print_string "\n"
    end;;

let compile_regex pattern =
    let prog = parse_compile_regex [] false true false pattern in
    let cache = Hashtbl.create 16 in
    cached_compile_state cache prog;;


let testme () =
    print_string "compiling...";
    let p = compile_regex "bar" in
    print_string "exploring...";
    explore_prog (Hashtbl.create 16) 0 p;
    let fsm = {t = Hashtbl.create 16; max = 0; all = []} in
    transform_prog_fsm fsm p;;

let _ =
    Printexc.record_backtrace true;
    let x = testme () in
    print x;;
