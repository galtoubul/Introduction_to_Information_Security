def check_message(path: str) -> bool:
    """
    Return True if `msgcheck` would return 0 for the file at the specified path,
    return False otherwise.
    :param path: The file path.
    :return: True or False.
    """
    with open(path, 'rb') as reader:
        # Separate input into rows of bytes
        rows = [[row[i:i+1] for i in range(len(row))] for row in reader]
        # Used https://stackoverflow.com/questions/952914/how-to-make-a-flat-list-out-of-a-list-of-lists
        chars = [ord(byte.decode('latin-1')) for row in rows for byte in row]     

        msg_len = chars[0]

        # Xoring bytes 2 to msg_len + 2 with 193
        s = 193
        for ind in range(2, msg_len + 2):
            if ind < len(chars):
                s ^= chars[ind]

        # chars[1] is the message signature
        if chars[1] == s:
            return True
        return False


def main(argv):
    if len(argv) != 2:
        print('USAGE: python {} <msg-file>'.format(argv[0]))
        return -1
    path = argv[1]
    if check_message(path):
        print('valid message')
        return 0
    else:
        print('invalid message')
        return 1


if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
