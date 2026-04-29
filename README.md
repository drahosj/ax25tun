# AX.25 Stack in Userspace
RIP kernel AX.25 stack, you will be dearly missed.

https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=64edfa65062d

Implements the missing parts of the kernel AX.25 stack in userspace using a TUN interface:

- Connects to Direwolf KISS-over-TCP (port 8001).
- AX.25 and KISS framing/de-framing for transmit and receive.
- Implements ARP for AX.25 (only ipv4 for now)

## Building

Normal cmake build process.

## Running
Make sure direwolf is running as normal (KISS TCP on port 8001).

Make sure nothing chatty will start trying to send lots of big
broadcast traffic (mDNS, QUIC stuff).

### Create and configure interface (only part that needs root)
Create a persistent tuntap interface with `ip tuntap add` and give a
non-root user permission to use the tuntap. Also configure
the interface normally and (try to) bring it up.

```
$ sudo ip tuntap add mode tun ax25tun0 user <your user>
$ sudo ip addr add 10.1.0.1/24 dev ax25tun0
$ sudo ip link set ax25tun0 up
```

Interface won't be up until ax25tun is running:
```
40: ax25tun0: <NO-CARRIER,POINTOPOINT,MULTICAST,NOARP,UP> mtu 1500 qdisc pfifo_fast state DOWN group default qlen 500
    link/none 
    inet 10.1.0.1/24 scope global ax25tun0
       valid_lft forever preferred_lft forever
    inet6 fe80::6b17:e932:cb7b:b79e/64 scope link stable-privacy proto kernel_ll 
       valid_lft forever preferred_lft forever
```

### Start ax25tun to bring up the "physical" layer of the tun interface

With iface created and configured, run ax25 to bring the link up:

```
$ ./ax25tun ax25tun0 <your call> <ssid>
```

Whenever ax25tun is running, iface will come up and work normally:
```
40: ax25tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 500
    link/none 
    inet 10.1.0.1/24 scope global ax25tun0
       valid_lft forever preferred_lft forever
    inet6 fe80::6b17:e932:cb7b:b79e/64 scope link stable-privacy proto kernel_ll 
       valid_lft forever preferred_lft forever

```

## Notes on operation
Outgoing packet flow
- Receive packets from `tunfd`
- Drop non-IPv4 packets
- Extract dst address
- Look up callsign for address in local ARP table
    - If found, transmit packet
    - If not found, send an ARP request to QST and queue packet for later transmit
    
Incoming packet flow
- If packet is ARP, handle internally
    - Populate/update ARP table with sender IP and sender callsign
    - If an ARP request for our IP, respond
    - iterate through pending packets queue and send any that match the newly-updated arp table
- Otherwise, write packet to tunfd to kick it to the kernel IP stack


## TODO
- ARP cache is very primitive. No expiration or anything like that.
- Transmit queue (for packets pending arp) is unlimited.
- IPv6 support
    - Should be possible to make ARP completely protocol agnostic by using char vectors/spans for addresses
    - Only thing needed is improvements to IP address finder (getifaddrs) and to pull the right size dstaddr out
    of the right place on the header
