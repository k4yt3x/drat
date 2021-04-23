# DRAT

DRAT is a simple RAT written in Python that communicates with the C&C server over DNS requests.

## Server Deployment

The required Python dependencies must be installed before the server is started. Use the following command to install all dependencies automatically:

```shell
pip3 install -U -r requirements.txt
```

After all dependencies are installed, some directory must be created to contain the PID file and the log file.

```shell
sudo mkdir /var/run/dratd /var/log/dratd
sudo chown -R nobody:nogroup /var/run/dratd /var/log/dratd
```

The server daemon can be controlled with the following commands:

```shell
# starting the server
sudo python3 dratd.py start

# stopping the server
sudo python3 dratd.py stop
```

## Client Deployment

There are two ways to start the DRAT client. You can either execute `drat.py` to run the client directly, or use the fake BTC mining client to launch it.

```shell
# launch the RAT directly
python3 drat.py

# launch the RAT via the fake BTC mining client
python3 totallySafe.py
```

The fake BTC mining client will double-fork a new process that launches the DRAT client before showing the GUI. The GUI does not have any practical functionalities. When the user finds that the program does not do what it should, there is a high probability that the user will close the GUI window. However, since the DRAT client is double-forked and has a PPID of 1 (init), the DRAT client will continue to run in the background until the system is shut-down.

## Client-Server Communications

Since the clients are expected to be behind NAT, this project uses the client/server communication model. The client will always the initiate the session. The UML diagram below shows a typical client-server communication.

```text
  +--------+               +--------+
  | Client |               | Server |
  +--------+               +--------+
      |  ------- HELLO ------>  |
      |  <----- COMMAND ------  |
      |  ------ RESULTS ----->  |
      |  <----- COMMAND ------  |
      |                         |
```

1. The client will send a HELLO packet to the server to initiate the session.
1. The server will reply with the command to be executed by the client.
1. The client will execute the command and return the execution results.
1. The server will reply with the next command to be executed. This cycle continues forever.

The code in this repository configures the server to instruct the client to execute the `CMD` command with the payload `ping -c1 -W1 1.1.1.1`. This will tell the client to send a single ICMP echo packet to 1.1.1.1. When the command finishes being executed, the server will issue the `SLEEP` command, which puts the client to sleep for 10 seconds. This communication will look like the diagram below:

```text
  +--------+                                      +--------+
  | Client |                                      | Server |
  +--------+                                      +--------+
      |  ---------- (CMD=HELLO, DATA=0x00) --------->  |
      |  <-------- (CMD=EXEC, DATA=ping...) ---------  |
      |  ------- (CMD=EXEC, DATA=return code) ------>  |
      |  <--------- (CMD=SLEEP, DATA=0x00) ----------  |
      |                                                |
```

### DNS Queries & Answers

The DNS queries are TXT requests following the following format:

```text
                                  1  1  1  1  1  1
    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                                               |
  /       QNAME (base64(payload).google.com)      /
  /                                               /
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                     QTYPE                     |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                     QCLASS                    |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

The DNS responses will base64-encode the payload in its answer section (RDATA).

```text
                                  1  1  1  1  1  1
    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                                               |
  /                                               /
  /                      NAME                     /
  |                                               |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                      TYPE                     |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                     CLASS                     |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                      TTL                      |
  |                                               |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                   RDLENGTH                    |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
  /            RDATA (base64(payload))            /
  /                                               /
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

### Custom Protocol Format

There is a custom protocol running on top of the DNS queries. The clients and servers decode the `payload` shown in the previous diagrams following the format shown below:

```text
                                  1  1  1  1  1  1
    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                     REQID                     |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |          CMD          |TR|      RESERVED      |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  /                     DATA                      /
  /                                               /
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

- REQID: A 16-bit long UUID4 which uniquely identifies this request/response. This UUID is used to correlate the request with its response.
- CMD: Command requested/executed. In server responses, this field indicates the command to be executed by the client. In client requests, this filed refers to the was executed.
- TR: Message truncated if set to 1 (not yet implemented). If this bit is set to 1, then it means that there is more to this message to be received.
- RESERVED: Unused reserved space.
- DATA: UTF-8-encoded multipurpose payload data. Its exact purpose depends on the context (CMD).

### CMD Values

Below are all of the values possible in the CMD field.

- 0x01 (ACK): Server ACK (reserved, unused)
- 0x02 (HELLO): Client hello, used to initiate the request
- 0x03 (INFO): Return system info
- 0x04 (EXEC): Execute a command
- 0x05 (SLEEP): Put the client to sleep

## Referenced Materials

The DNS protocol is implemented following the specifications outlined in the two following documents:

- https://tools.ietf.org/html/rfc1035
- https://tools.ietf.org/html/rfc2535

While writing this project, I have also found this following tutorial to be helpful:

- https://routley.io/posts/hand-writing-dns-messages/
