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

With iface created and configured, run ax25 to bring the link up:

```
$ ./ax25tun ax25tun0 <your call> <ssid>
```

Whenever ax25tun is running, iface will come up and work normally:
```
% ip a sh dev ax25tun0 | cat
40: ax25tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 500
    link/none 
    inet 10.1.0.1/24 scope global ax25tun0
       valid_lft forever preferred_lft forever
    inet6 fe80::6b17:e932:cb7b:b79e/64 scope link stable-privacy proto kernel_ll 
       valid_lft forever preferred_lft forever

```

## TODO
- ARP cache is very primitive. No expiration or anything like that.
- Transmit queue (for packets pending arp) is unlimited.
- Major refactor needed
- IPv6 support
