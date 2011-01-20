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

open Int64;
module Buffer = struct
  type t = {
    buf64 : mutable int64;
    used: mutable int;
    buf : Buffer.t;
  };

  value create () = {buf64 = 0_L; used = 0; buf = Buffer.create 4096};

  (* convert an int64 to little-endian bytes *)
  value lebytes_of_int64 i =
    let char_of_int64 x = Char.unsafe_chr (to_int (logand x 0xff_L))
    and s = String.create 8 in
    (String.unsafe_set s 0 (char_of_int64 i);
    String.unsafe_set s 1 (char_of_int64 (shift_right_logical i 8));
    String.unsafe_set s 2 (char_of_int64 (shift_right_logical i 16));
    String.unsafe_set s 3 (char_of_int64 (shift_right_logical i 24));
    String.unsafe_set s 4 (char_of_int64 (shift_right_logical i 32));
    String.unsafe_set s 5 (char_of_int64 (shift_right_logical i 40));
    String.unsafe_set s 6 (char_of_int64 (shift_right_logical i 48));
    String.unsafe_set s 7 (char_of_int64 (shift_right_logical i 56));
    s);

  (* add the specified amount of low-order bits from val64 *)
  value add_bits b val64 bits =
    let maxshift = min (64 - b.used) bits in do {
    (* check that nothing is lost by outputting only the specified amount of
     * bits, considering that the loader sign-extends *)
    assert ((shift_right_logical val64 bits) = 0_L ||
    ((shift_right val64 bits) = (-1_L) || bits = 64));
    b.buf64 := logor (shift_right_logical b.buf64 maxshift) (shift_left val64 (64 - maxshift));
    b.used := b.used + maxshift;
    if b.used = 64 then do {
      Buffer.add_string b.buf (lebytes_of_int64 b.buf64);
      b.used := bits - maxshift;
      b.buf64 := shift_left val64 (64 - b.used);
    } else ();
    };

    (* add the specified bytes to the buffer, not necesarely aligned on byte
     * boundary *)
   value add_string_bits b str = do {
     let add_char c = add_bits b (of_int (Char.code c)) 8 in
     String.iter add_char str;
   };

   (* flush bits to next byte boundary *)
   value flush_bits b =
     if b.used > 0 then
       let v = shift_right_logical b.buf64 (64 - b.used) in
       let s = String.sub (lebytes_of_int64 v) 0 ((b.used + 7)/8) in do {
       Buffer.add_string b.buf s;
       b.used := 0;
       b.buf64 := 0_L;
     }
     else ();

   (* add a character to the buffer, aligned on byte boundary *)
   value add_char b c = do {
     flush_bits b;
     Buffer.add_char b.buf c;
   };

   (* add a string to the buffer, aligned on byte boundary *)
   value add_string b str = do {
     flush_bits b;
     Buffer.add_string b.buf str;
   };

   (* retrieve bytes *)
   value retrieve_and_reset b =
     let s = Buffer.contents b.buf in
     do {
       Buffer.reset b.buf;
       b.used := 0;
       b.buf64 := 0_L;
       s;
     };
end;

value lengthof val64 =
  if (compare val64 0xffffffff_L) <= 0 then do {
    if (compare val64 0xffff_L) <= 0 then do {
      if (compare val64 0xff_L) <= 0 then 1 else 2;
     } else do {
       if (compare val64 0xffffff_L) <= 0 then 3 else 4;
     }
  } else do {
    if (compare val64 0xffffffffffff_L) <= 0 then do {
      if (compare val64 0xffffffffff_L) <= 0 then 5 else 6;
    } else do {
      if (compare val64 0xffffffffffffff_L) <= 0 then 7 else 8;
    }
  };

(* add bits in sign + length + bits encoding *)
value add_bits_vbr b val64 =
  let abs_val = abs val64 in do {
    Buffer.add_bits b (if abs_val == val64 then 1_L else 0_L) 1;
    let length = lengthof abs_val in do {
      Buffer.add_bits b (of_int (length-1)) 3;
      let len = if length = 8 then 63 else length*8 in
      Buffer.add_bits b abs_val len;
    }
  };

value add_bits_vbroff b val_i =
  let val64 = Int64.of_int val_i in
  if (val64 == 0_L) then
    Buffer.add_bits b 0_L 1
  else do {
    Buffer.add_bits b 1_L 1;
    if (compare val64 0xff_L) <= 0 then do {
      Buffer.add_bits b 0_L 1;
      Buffer.add_bits b val64 8;
    } else do {
      Buffer.add_bits b 1_L 1;
      Buffer.add_bits b val64 32;
    }
  };

value add_bits_vbrlow b val_i =
  let val64 = Int64.of_int val_i in
  match lengthof val64 with
  [ 1 -> do {
    Buffer.add_bits b 0_L 1;
    Buffer.add_bits b val64 8;
   }
  | 2 -> do {
    Buffer.add_bits b 1_L 1;
    Buffer.add_bits b 0_L 1;
    Buffer.add_bits b val64 16;
   }
  | 3 | 4 -> do {
    Buffer.add_bits b 1_L 1;
    Buffer.add_bits b 1_L 1;
    Buffer.add_bits b val64 32;
   }
  | _ -> assert False ];

value add_nul_string b str = do {
  Buffer.add_string b str;
  Buffer.add_char b '\000';
};

(* vim: set sw=2: *)
