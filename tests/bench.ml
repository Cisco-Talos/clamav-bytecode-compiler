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

let n = 1 in (* in megabytes *)
let f = Unix.gettimeofday() in
let s = Encode.create_file ~name:"BC.test" ~flags:"" ~logical_sig:"" ~min_func:0 ~max_func:0 ~sigmaker:"sigmaker" ~out:(open_out_bin "/tmp/foo.cbc") in
(
Encode.new_section s Sectiontypes.SectionDataInit;
Printexc.record_backtrace True;
let b = Encode.get_buffer s in
for i = 0 to n*1024*1024 do
    Bits.Buffer.add_bits b (Int64.of_int i) 64;
done;
Encode.end_section s;
Encode.end_file s;
let t1 = Unix.gettimeofday () in
(for i = 0 to n*1024*1024 do
    ignore (Int64.of_int i);
done;
let t2 = (Unix.gettimeofday ()) in
let t = t1 -. f in
let t_0 = t2 -. t1 in
Printf.eprintf "time: %fs, %fMB/s\n " (t -. t_0) (8.0*.(float_of_int n) /. (t-.t_0));
));
(* vim: set sw=2: *)
