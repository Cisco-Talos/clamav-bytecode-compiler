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

open Cryptokit;
open Int64;
open Sectiontypes;

module BB = Bits.Buffer;

(* For backwards compatibility with ClamAV 0.96.1 lines can't be longer than 4k.
 * If lines are longer then 0.96.1 will show a warning when attempting to skip
 * the file.
 * We must allow for newlines, and its better to keep it 4-bytes aligned hence the -4.
 *)
value linesize = 4096 - 4;

(* pointers are represented with a zone-id and an offset.
 * For now it is 2-bits of zone-id and 32-bits of offset (and 30-bits TBD),
 * but maybe we can use 2-bits of zone-id and 30-bit offset.
 *)
type ptrzone = [ PtrNull | PtrGlobal | PtrHeap | PtrStack ];

type bytecode_file = {
    bitbuffer : BB.t;
    filebuf : Buffer.t;
    name : string;
    flags : string;
    logical_sig : string;
    sigmaker : string;
    min_func : int;
    max_func : int;
    out : out_channel;
    hash : Cryptokit.hash;
    section_type : mutable section;
    functions : mutable int;
    max_functionid: mutable int;
    global_bytes: mutable int;
    sections: mutable int;
};

value set_global_bytes file b = file.global_bytes := b;

value set_functions file functions maxid = do {
  file.functions := functions;
  file.max_functionid := maxid;
};

value create_file ~out ~name ~flags ~logical_sig ~sigmaker ~min_func ~max_func = {
    bitbuffer = BB.create ();
    filebuf = Buffer.create 16384;
    name = name;
    flags = flags;
    logical_sig = logical_sig;
    sigmaker = sigmaker;
    min_func = min_func;
    max_func = max_func;
    out = out;
    hash = Cryptokit.Hash.sha256 ();
    section_type = SectionNone;
    functions = 0;
    max_functionid = 0;
    global_bytes = 0;
    sections = 0;
};

value get_buffer file = file.bitbuffer;

value add_bits file = BB.add_bits file.bitbuffer;
value flush_bits file = BB.flush_bits file.bitbuffer;
value retrieve_and_reset file = BB.retrieve_and_reset file.bitbuffer;
value add_bits_vbr file = Bits.add_bits_vbr file.bitbuffer;
value add_bits_vbroff file = Bits.add_bits_vbroff file.bitbuffer;
value add_bits_vbrlow file = Bits.add_bits_vbrlow file.bitbuffer;
value add_string file = BB.add_string file.bitbuffer;
value add_char file = BB.add_char file.bitbuffer;
value add_nul_string file = Bits.add_nul_string file.bitbuffer;
value add_zeroes file size = do {
  BB.flush_bits file.bitbuffer;
  BB.add_string file.bitbuffer (String.make (Int64.to_int size) '\000');
};

value add_pointer file zone ptroff =
    let zonebit =
        match zone with
        [ PtrNull -> 0_L
        | PtrGlobal -> 1_L
        | PtrHeap -> 2_L
        | PtrStack -> 3_L ] in
    do {
      add_bits file zonebit 2;
      add_bits file 0_L 30;
      add_bits file (of_int ptroff) 32;
    };

value add_string_varlength file str = do {
  add_bits_vbr file (Int64.of_int (String.length str));
  add_string file str;
};

value end_section file =
    let filebuf = file.filebuf in
    let filter str =
      if (String.length str > 1) then
          let prev = 0x42  in
          for i = 0 to (String.length str) - 1 do {
            let c = Char.code str.[i] in
            str.[i] := Char.chr ((c - prev) land 0xff);
          }
      else ()
    and output_delimited str =
        let len = String.length str
        and i = ref 0
        in
        while i.val < len do {
            let linelen = min (len - i.val) linesize;
            Buffer.add_substring filebuf str i.val linelen;
            Buffer.add_char filebuf '\n';
            i.val := i.val + linelen;
        }
    in do {
    flush_bits file;
    let data = retrieve_and_reset file
    and section_type_id = Hashtbl.hash file.section_type;
    let compressed = Cryptokit.transform_string (Cryptokit.Zlib.compress ~level: 9()) data;
    file.hash#add_byte section_type_id;
    file.hash#add_string data;
    add_bits_vbr file (of_int (String.length data));
    add_bits file (of_int section_type_id) 8;
    flush_bits file;
    add_string file compressed;
    let data2 = retrieve_and_reset file;
    filter data2;
    Buffer.add_char filebuf (if is_loadable file.section_type then 'L' else 'I');
    output_delimited (Cryptokit.transform_string (Base64.encode_compact ()) data2);
    file.section_type := SectionNone;
    };

value end_file file = do {
    assert (file.section_type = SectionNone);
    file.section_type := SectionHeader;
    add_bits file (of_float (Unix.time ())) 64;
    add_bits file (of_int file.sections) 32;
    add_bits file (of_int file.functions) 32;
    add_bits file (of_int file.global_bytes) 32;
    add_bits file (of_int file.min_func) 8;
    add_bits file (of_int file.max_func) 8;
    flush_bits file;
    add_nul_string file Version.version;
    add_nul_string file Version.compile_time;
    add_nul_string file Sys.ocaml_version;
    add_nul_string file Sys.os_type;
    add_nul_string file (string_of_int Sys.word_size);
    add_nul_string file (Version.sys_uname);
    add_nul_string file file.sigmaker;
    add_nul_string file file.flags;
    let headbuf = retrieve_and_reset file in do {
        file.hash#add_string headbuf;
        file.hash#add_string file.name;
        add_string file file.hash#result;
        let header =
            Cryptokit.transform_string (Base64.encode_compact ())
            headbuf in do {
                assert ((String.length header) < linesize - 4);
                assert ((String.length file.name) < linesize);
                output_string file.out "ClamBCah";
                output_string file.out header;
            };
    };
    output_char file.out '\n';
    output_string file.out file.name;
    output_char file.out '\n';
    output_string file.out (Buffer.contents file.filebuf);
    close_out file.out;
    Buffer.reset file.filebuf;
};

value new_section file t = do {
    if file.section_type <> SectionNone then end_section file else ();
    file.section_type := t;
    file.sections := file.sections + 1;
};
(* vim: set sw=2: *)
