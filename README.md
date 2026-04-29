# AX.25 Stack in Userspace
RIP kernel AX.25 stack, you will be dearly missed.

https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=64edfa65062d

This is the start of a stack to implement the necessary bits to connect a TUN
interface to a KISS TNC. The main goal will be to
support the Direwolf's KISS-over-TCP interface.

Honestly, it shouldn't be that much code:

### Transmit
- Create TUN interface (done)
- Lookup destination address from an internal ARP table (done for ipv4)
- Send ARP request for unresolved addresses (done)
- Enqueue packets pending ARP resolution (done)
- Encapsulate IP packets in AX.25 and KISS then send to Direwolf (done)

### Receive
- Synchronize to KISS stream (done)
- De-encapsulate KISS and process (done)
- Respond to ARP requests (done)
- Populate ARP table from ARP responses and send queued packets (done)
- De-encapsulate matching unicast frames and pass to TUN (done)


### Housekeeping
- epoll loop (done)
- ARP housekeeping?


## ax25tun is now fully working!
With direwolf running as normal (KISS TCP on port 8001).

```
$ g++ -o ax25tun --std=c++23 ax25tun.cpp
$ sudo ./ax25tun <ifname> <mycall> <ssid>
# eg: sudo ./ax25tun ax25tun0 WN0NW 1

# configure iface with IP
$ sudo ip addr add 10.1.0.1/24 dev ax25tun0
$ sudo ip link set ax25tun0 up
```


Should now be able to ping over interface or do UDP. Don't do TCP.

Make sure nothing chatty will start trying to send lots of big
broadcast traffic (mDNS, QUIC stuff).

Interacts well with kernel ax.15 stack running on another computer.

### Use persistent tuntap interfaces to not have to run this thing as root
Create a persistent tuntap interface with `ip tuntap add` and give a
non-root user permission to use the tuntap:

```
$ sudo ip tuntap add mode tun ax25tun0 user <your user>
$ ./ax25tun ax25tun0 <your call> <ssid>
```
It should attach to the existing interface.

Can now configure interface normally (as root)

```
$ sudo ip addr add 10.1.0.1/24 dev ax25tun0
$ sudo ip link set ax25tun0 up
```


## TODO
- ARP cache is very primitive. No expiration or anything like that.
- Transmit queue (for packets pending arp) is unlimited.
- Major refactor needed
- IPv6 support
