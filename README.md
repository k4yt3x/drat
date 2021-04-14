# DRAT

A simple RAT written in Python that communicates with the C&C server over DNS requests.

## DNS Specifications

- https://tools.ietf.org/html/rfc1035
- https://tools.ietf.org/html/rfc2535

## Packets

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
- CMD: Command requested/executed
- TR: Message truncated if set to 1 (not implemented)
- RESERVED: Unused reserved space
- DATA: UTF-8-encoded multipurpose payload data

### CMD Values

- 0x01 (ACK): Server ACK
- 0x02 (HELLO): Client hello, used to initiate the request
- 0x03 (INFO): Return system info
- 0x04 (EXEC): Execute a command
- 0x05 (SLEEP): Put the client to sleep
