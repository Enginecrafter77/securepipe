# securepipe
A simple command line utility used for quickly transferring large volume of data between networked machines.

## Overview
The general working principle of securepipe is best illustrated with the following diagram:

```
/------\           /------------\                        /---------------\            /------\
| data | ===STDIN> | securepipe | =~~=Encrypted data=~~= | securepipe -d | STDOUT===> | data |
\------/           \------------/                        \---------------/            \------/

<-------------Host1-------------> <-------Network------> <---------------Host2--------------->
```

On one machine, securepipe runs in encrypting mode, where plaintext data is read from standard input, and encrypted data is sent over the network.
On the other side, securepipe runs in decrypting mode (denoted by `-d` switch), where encrypted data is received from network, and plaintext data is written back to standard output.

When establishing connection, securepipe can run in either client or server mode. In server mode, the process waits until client connects to it, and only
then the data starts being encrypted/decrypted. In client mode, securepipe connects to a remote machine running securepipe server process. After connection
is established, the data can start flowing.

You can freely mix the configurations. Securepipe can be run in all 4 modes: encrypting server, decrypting server, encrypting client, decrypting client.

All data sent over the network is encrypted using AES-256-GCM algorithm. When the connection is first initiated, 2 diffie-hellman based key exchanges occur: one in which the encryption key is decided on, and the second where the random number generator seed is decided on. Then, for every block, a new 96-bit nonce is generated using the aforementioned random number generator. Assuming that both ends run the same code, the both random number generators should generate the same sequences of numbers, thus nonces will stay in sync.

## Usage
A simple example use case (assuming machine2 is able to reach machine1)

machine1:
```sh
cat /var/log/messages.log | securepipe -vv`
```

machine2:
```sh
securepipe -vv -d machine1.local > messages.log
```

As can be seen in the example above, by default securepipe runs in encrypting mode. The decrypting mode can be selected by adding the `-d` switch.
Moreover, whether securepipe behaves as client or server is given by the presence of an optional free-standing argument to the executable denoting client's address. If the argument is present (see machine2 example), securepipe tries to connect to the given host (`machine1.local` in the above example). If the
argument is absent, securepipe behaves as server and listens for a connection.

By default, securepipe uses TCP port `4096`. This can be changed by specifying `-p <port>` option.

### Direct file I/O
One can also use securepipe without relying on standard input/output streams as such:
machine1:
```sh
securepipe -vv -i /var/log/messages.log`
```

machine2:
```sh
securepipe -vv -d -o messages.log machine1.local
```
where the `-i <infile>` option specifies that input should be read from `infile` instead of standard input, and `-o <outfile>` specifies that output should be
written to `outfile` instead of standard output.

## Disclaimer
Even though the name has "secure" in it, no actual security analysis was performed and the only reason why I called it "secure" was that it was actually encrypted. I made this program since I wanted to transfer large backup files between my PC and a remote server. `scp` was just way too slow, and plain netcat was too insecure. Thus, I made this. I'm sharing this in hopes that it might become useful to someone in the future. - Enginecrafter77
