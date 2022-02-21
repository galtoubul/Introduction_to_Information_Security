import socket


def send_message(ip, port):
    connection = socket.socket()
    try:
        connection.connect((ip, port))
        connection.send(b'I love you')
    finally:
        connection.close()


def main():
    send_message('127.0.0.1', 1984)


if __name__ == '__main__':
    main()
