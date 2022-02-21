def fix_message_data(data: bytes) -> bytes:
    """
    Implement this function to return the "fixed" message content. This message
    should have minimal differences from the original message, but should pass
    the check of `msgcheck`.

    The fix in this file should be *different* than the fix in q1b.py.

    :param data: The source message data.
    :return: The fixed message data.
    """
    # Find the desired signature
    msg_len = data[0]
    s = 193
    for ind in range(2, msg_len + 2):
        if ind < len(data):
            s ^= data[ind]

    # Add a byte at the end of "checking zone"(2, ..., 2+msg_len)
    # such that it will fit the given signature
    if data[1] != s:
        bytes_list = list(data)
        bytes_list.insert(data[0] + 2, data[1] ^ s)
        bytes_list[0] += 1
        data = bytes(bytes_list)
    
    return data


def fix_message(path):
    with open(path, 'rb') as reader:
        data = reader.read()
    fixed_data = fix_message_data(data)
    with open(path + '.fixed', 'wb') as writer:
        writer.write(fixed_data)


def main(argv):
    if len(argv) != 2:
        print('USAGE: python {} <msg-file>'.format(argv[0]))
        return -1
    path = argv[1]
    fix_message(path)
    print('done')


if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
