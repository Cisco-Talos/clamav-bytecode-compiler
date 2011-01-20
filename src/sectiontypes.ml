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

type section =
  [ SectionNone
  | SectionHeader
  | SectionCopyright
  | SectionSource
  | SectionLink
  | SectionDataInit
  | SectionDataZero
  | SectionDataPtr
  | SectionCode
  | SectionGenericMetadata
  | SectionDebug ];

(* Indicates whether normal loading of bytecode should load this section.
 * This can be used to quickly skip over sections that are not needed for
 * bytecode execution *)
value is_loadable s =
  match s with
  [ SectionNone | SectionHeader -> assert False
  | SectionCopyright | SectionSource -> False
  | SectionLink | SectionDataInit | SectionDataZero | SectionDataPtr |
      SectionCode | SectionGenericMetadata -> True
  | SectionDebug -> False ];

(* vim: set sw=2: *)
