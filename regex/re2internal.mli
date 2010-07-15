type regex
exception Error of string
type roption =
    [ `CASE_INSENSITIVE
    | `LITERAL
    | `LONGEST_MATCH
    | `MAX_MEM of int
    | `NEVER_NL
    | `NOLOG_ERRORS
    | `ONE_LINE
    | `PERL_CLASSES
    | `POSIX_SYNTAX
    | `UTF8
    | `WORD_BOUNDARY ]
external parse_regex : roption list -> string -> regex = "re2i_parse"
type transitions = (char array * state Lazy.t) list
and state =
    [ `DeadState
    | `FullMatchState
    | `GenericState of transitions
    | `SelfLoopState of transitions ]
and raw_state
and raw_regex_prog
and regex_prog = (raw_state, state) Hashtbl.t * raw_regex_prog
external compile_regex : bool -> bool -> regex -> raw_regex_prog
  = "re2i_compile_regex"
type raw_inst
exception DFAOutOfMemory
external prog_startrawstate : bool -> raw_regex_prog -> raw_state
  = "re2i_prog_startstate"
type raw_transitions = raw_state array
external explore_raw_state :
  bool -> raw_regex_prog -> raw_state -> raw_transitions
  = "re2i_explore_state"
type state_class = Generic | Dead | FullMatch
external classify_raw_state : raw_state -> state_class
  = "re2i_classify_state"
external dump_state : raw_state -> unit = "re2i_dump_state"
