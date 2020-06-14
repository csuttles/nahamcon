#!/usr/bin/env python3

import re
import readline
import socket
import time

host = 'jh2i.com'
port = 50034
msg = ''
letters = 'abcdefghijklmnopqrstuvwxyz'
LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'


def newclient(host, port):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((socket.gethostbyname(host),port))
    return client


def recvall(sock):
    BUFF_SIZE = 4096 # 4 KiB
    data = b''
    while True:
        part = sock.recv(BUFF_SIZE)
        data += part
        if len(part) < BUFF_SIZE:
            # either 0 or end of data
            break
    return data


def parseresp(dat):
    # send back this line exactly. character 13 of the flag is 'k'
    flagchar = bytes
    flagpos = 999999
    #print('start regex')
    msg = dat
    match = re.search(rb"send back this line exactly. character (?P<flagpos>\d+) of the flag is '(?P<flagchar>.*?)'", dat)
    if match:
        #print('matched regex')
        flagchar = match.group('flagchar')
        flagpos = int(match.group('flagpos'))
    if flagchar and flagpos != 999999:
        return msg, flagchar, flagpos, False
    elif dat.decode("utf-8").strip('\n').endswith('filler.'):
        return msg, None, None, True
    else:
        return msg, None, None, False

def decrypt(n, ciphertext):
    """Decrypt the string and return the plaintext"""
    result = ''

    for l in ciphertext:
        try:
            if l.isupper():
                index = LETTERS.index(l)
                i =  (index - n) % 26
                result += LETTERS[i]
            else:
                index = letters.index(l)
                i =  (index - n) % 26
                result += letters[i]

        except ValueError:
            result += l

    return result


def main():
    # set flag to 80 char string
    flag = [' ' for x in range(1000)]
    client = newclient(host, port)
    dat = recvall(client)
    #if dat == rb'send back this line exactly. no flag here, just filler.':
    client.send(rb'send back this line exactly. no flag here, just filler.')
    dat = recvall(client)
    while True:
        try:
            for n in range(0, 26):
                time.sleep(0.01)
                sendit = False
                dec = decrypt(n,
                dat.decode("utf-8"))
                # noisy but useful
                # print(f"{n} - '{dec}'", end='')
                msg, char, pos, sendit = parseresp(dec.encode("utf-8"))
                if char and pos!= 999999:
                    # print(f'match pos: {pos} and char: {char}', dec)
                    flag[pos] = char.decode("utf-8")
                    FLAG = (''.join(flag)).rstrip()
                    print('\b' * (len(flag) + 20), f'FLAG: "{FLAG}"', end='')
                    client.send(msg)
                    dat = recvall(client)
                    break
                if sendit:
                    #print('just send it!')
                    client.send(msg)
                    dat = recvall(client)
                    break
        except socket.error:
            print('oops')
            client.close()
            break
        except KeyboardInterrupt:
            client.close()
            break
    client.close()
    print('\b' * (len(flag) + 20), f'FLAG: "{FLAG}"', end='')



if __name__ == '__main__':
    main()

