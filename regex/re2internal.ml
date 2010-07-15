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
type regex (** Parsed regular expression *)
exception Error of string

(** regex compilation options *)
type roption =
    [ `UTF8             (** text and pattern are UTF-8; otherwise Latin-1 *)
    | `POSIX_SYNTAX     (** restrict regexps to POSIX egrep syntax *)
    | `LONGEST_MATCH    (** search for longest match, not first match *)
    | `NOLOG_ERRORS     (** don't log syntax and execution errors to ERROR *)
    | `MAX_MEM of int   (** approx. max memory footprint *)
    | `LITERAL          (** interpret string as literal, not regexp *)
    | `NEVER_NL         (** never match \n, even if it is in regexp *)
    | `CASE_INSENSITIVE (** match is case-insensitive (regexp can override with
                            (?-i) unless in POSIX_SYNTAX mode) *)
    | `PERL_CLASSES     (** allow Perl's \d \s \w \D \S \W when in POSIX_SYNTAX
                            mode *)
    | `WORD_BOUNDARY    (** allow \b \B (word boundary and not) when in
                            POSIX_SYNTAX *)
    | `ONE_LINE         (** ^ and $ only match beginning and end of text when in
                            POSIX_SYNTAX mode *)
    ]

external parse_regex :
    roption list ->
    string -> regex = "re2i_parse"
    (** [compile_regex ?options pattern] compiles [pattern] with [flags].
     * @return the compiled regular expression.
     *)

type transitions = (char array * state Lazy.t) list
and  state =
    [ `DeadState (** this state can never lead to a match *)
    | `FullMatchState (** match (regardless of rest of the string ) *)
    | `SelfLoopState of transitions (** a state with a selfloop and some other transitions *)
    | `GenericState of transitions  (** a state without a selfloop and some other transitions *)
    ]
and raw_state
and raw_regex_prog
and regex_prog = ((raw_state, state) Hashtbl.t) * raw_regex_prog

external compile_regex :
    bool ->
    bool ->
    regex -> raw_regex_prog = "re2i_compile_regex"
    (** gives the regex program corresponding to the regex *)

type raw_inst (** raw Prog::Inst* *)

(*let prog_startstate :
    regex_prog -> state Lazy.t;;*)
    (** gives the start state for the given prog *)

exception DFAOutOfMemory
external prog_startrawstate:
    bool -> raw_regex_prog -> raw_state = "re2i_prog_startstate"

(*external insts_of_state :
    raw_state -> raw_inst list = "re2i_insts_of_state"*)

(** TODO: a type for raw_inst *)
type raw_transitions = raw_state array;;
external explore_raw_state :
    bool -> raw_regex_prog -> raw_state -> raw_transitions = "re2i_explore_state";;

type state_class = Generic | Dead | FullMatch;;
external classify_raw_state : raw_state -> state_class = "re2i_classify_state";;

let analyze_transitions trans =
    if Array.length trans == 0 then
        []
    else begin
    let tbl = Hashtbl.create 257 in
    let build_transition s =
        (Array.of_list (Hashtbl.find_all tbl s), s) in
    let states = ref [] in
    for i = 0 to 255 do begin
        let state = trans.(i) in
        if not (Hashtbl.mem tbl state) then
            states := state :: !states;
        Hashtbl.add tbl trans.(i) (char_of_int i);
    end
    done;
    if classify_raw_state trans.(256) <> Dead then begin
        match (classify_raw_state trans.(256)) with
        Generic -> print_string "Generic"
        | Dead -> print_string "Dead"
        | FullMatch -> print_string "Match";
        raise (Failure "EOF must go to deadstate for now");
    end;
    List.map build_transition !states
    end;;

let rec dump r =
        if Obj.is_int r then
                string_of_int (Obj.magic r : int)
        else (* Block. *)
        let rec get_fields acc = function
                | 0 -> acc
                | n -> let n = n-1 in get_fields (Obj.field r n :: acc) n
        in
    let rec is_list r =
                if Obj.is_int r then
                        r = Obj.repr 0 (* [] *)
                else
                        let s = Obj.size r and t = Obj.tag r in
                        t = 0 && s = 2 && is_list (Obj.field r 1) (* h :: t *)
        in
    let rec get_list r =
                if Obj.is_int r then
                        []
                else 
                        let h = Obj.field r 0 and t = get_list (Obj.field r 1) in
                        h :: t
    in
    let opaque name =
                (* XXX In future, print the address of value 'r'.  Not possible in
                * pure OCaml at the moment.
                *)
                "<" ^ name ^ ">"
    in
    let s = Obj.size r and t = Obj.tag r in
    (* From the tag, determine the type of block. *)
        match t with 
        | _ when is_list r ->
                let fields = get_list r in
                "[" ^ String.concat "; " (List.map dump fields) ^ "]"
        | 0 ->
                let fields = get_fields [] s in
                "(" ^ String.concat ", " (List.map dump fields) ^ ")"
        | x when x = Obj.lazy_tag ->
                (* Note that [lazy_tag .. forward_tag] are < no_scan_tag.  Not
                * clear if very large constructed values could have the same
                * tag. XXX *)
                opaque "lazy"
        | x when x = Obj.closure_tag ->
                opaque "closure"
        | x when x = Obj.object_tag ->
                let fields = get_fields [] s in
                let clasz, id, slots =
                        match fields with
                        | h::h'::t -> h, h', t 
                        | _ -> assert false
                in
                (* No information on decoding the class (first field).  So just print
                * out the ID and the slots. *)
                "Object #" ^ dump id ^ " (" ^ String.concat ", " (List.map dump slots) ^ ")"
    | x when x = Obj.infix_tag ->
                opaque "infix"
    | x when x = Obj.forward_tag ->
                opaque "forward"
        | x when x < Obj.no_scan_tag ->
                let fields = get_fields [] s in
                "Tag" ^ string_of_int t ^
                " (" ^ String.concat ", " (List.map dump fields) ^ ")"
        | x when x = Obj.string_tag ->
                "\"" ^ String.escaped (Obj.magic r : string) ^ "\""
        | x when x = Obj.double_tag ->
                string_of_float (Obj.magic r : float)
        | x when x = Obj.abstract_tag ->
                opaque "abstract"
        | x when x = Obj.custom_tag ->
                opaque "custom"
        | x when x = Obj.final_tag ->
                opaque "final"
        | _ ->
                failwith ("Std.dump: impossible tag (" ^ string_of_int t ^ ")")

let dump v = dump (Obj.repr v)

let print v = print_endline (dump v)

let rec explore_lazy_state (longestmatch:bool) (prog : regex_prog) rawstate : state =
    let convert_raw_transitions (bytes, s) =
            match Hashtbl.find_all (fst prog) s with
            | [] -> (bytes, lazy (explore_lazy_state longestmatch prog s))
            | h :: [] -> (bytes, lazy h)
            | _ -> raise (Failure "hashtable contains duplicate values")
    in
    match Hashtbl.find_all (fst prog) rawstate with
    | [] ->
        let explored_raw = explore_raw_state longestmatch (snd prog) rawstate in
        let explored = analyze_transitions explored_raw in
        (let (selfloop, nonselfloop) =
            List.partition (fun (b, s) -> s = rawstate) explored in
        let has_selfloop = List.length selfloop >= 1 in
        let specialstate = classify_raw_state rawstate in
        let trans = List.map convert_raw_transitions nonselfloop in
        let result =
            match specialstate, has_selfloop with
              |	Dead, _ -> `DeadState
              | FullMatch, _ -> `FullMatchState
              | Generic, true -> `SelfLoopState trans
              | Generic, false -> `GenericState trans in
        Hashtbl.add (fst prog) rawstate result;
        result);
     | h :: [] -> h
     | _ -> raise (Failure "hashtable contains duplicate values");;

let prog_startstate ~longestmatch prog =
  explore_lazy_state longestmatch prog (prog_startrawstate longestmatch (snd prog));;

let next_state (s:state) (c:char) : state =
    let has_trans x =
        List.mem c (Array.to_list (fst x)) in
    match s with
       | `DeadState | `FullMatchState -> s
       | `SelfLoopState trans ->
               (match List.filter has_trans trans with
               | [] -> s
               | h :: t -> Lazy.force (snd h));
       | `GenericState trans ->
               Lazy.force (snd (List.find has_trans trans));;

let parse_compile_regex options anchored forward longestmatch pattern =
    let parsed = parse_regex options pattern in
    let compiled = compile_regex anchored forward parsed in
    let prog = (Hashtbl.create 128, compiled) in
    let estate = prog_startstate longestmatch prog in
    estate;;


