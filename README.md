# microps-zig

microps-zig is a Zig reimplementation of [microps](https://github.com/pandax381/microps), a small TCP/IP stack for learning.

It supports Ethernet and loopback devices, ARP, IPv4, ICMP, UDP, TCP, and a socket-like C API.

## Requirements

- Linux (tested on Ubuntu 26.04 LTS)
- Zig 0.16.0
- `iproute2`

## Build

```sh
zig build
zig build -Dhexdump=true # Enable packet hexdumps
```

## Examples

### TCP echo server

Create `tap0` and start the Zig example:

```sh
zig build tap # Uses sudo
zig build run
```

The host uses `192.0.2.1/24` and microps-zig uses `192.0.2.2/24`.
Test from another terminal:

```sh
ping 192.0.2.2
nc 192.0.2.2 7
```

### Socket-like C API

`include/sock.h` provides the socket-like C API. 
Run its TCP echo server with:

```sh
zig build run-example
```

## License

microps-zig is licensed under the MIT License. See [LICENSE](LICENSE).

The original microps is also licensed under the MIT License.
See [LICENSE.microps](LICENSE.microps) for details.
