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
(* exceptions *)

(* location value, detail value *)
value context = global_context ();
type location = [ Val of llvalue | Ty of lltype | Mod of llmodule ];

exception NotSupported of string and location;
exception OutOfBounds of string and location;
exception NotSupportedYet of string and location;
exception UndefError of string and location;
exception LogicError of string and location;
exception FormatError of string and option llvalue;
exception ConfigError of string and string;
exception NotImplemented of llvalue and llvalue;
exception LinkerError of string and llvalue;
exception UndefinedExternalError of string and llvalue;

exception Internal of string and option string and location and exn;
(* vim: set sw=2: *)
