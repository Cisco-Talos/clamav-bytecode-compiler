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

open Compiler;

at_exit Gc.full_major; (* make valgrind happy *)

(Printexc.record_backtrace True;
 if (Array.length Sys.argv) <> 3
 then
   (prerr_string "Usage: ";
    prerr_string Sys.argv.(0);
    prerr_string " <filename> <outputfile>\n";
    exit 1)
 else
   compile Sys.argv.(1) Sys.argv.(2));

(* vim: set sw=2: *)

