# send-arp
- control victim's arp table (target ip -> attacker mac)

### Example
```
syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]
sample : send-arp ens33 172.30.1.31 172.30.1.254
```
```bash
$ sudo ./send-arp ens33 172.30.1.31 172.30.1.254
[+] attacker ip addr: ***.**.1.55
[+] attacker mac addr: **:**:**:**:77:6e
[+] sender ip addr: 172.30.1.31
[+] sender mac addr: **:**:**:**:2a:df
[+] target ip addr: 172.30.1.254
```

### Results
![KakaoTalk_Photo_2020-10-13-19-13-27](https://user-images.githubusercontent.com/64528476/95847840-2efd5600-0d88-11eb-8d52-5fa149d08ced.png)


### Some problem
- When I want to get the victim's mac address, until he gives me the reply packet, I request the a lot of request packet.
- I think I can solve this problem by thread programming, but I failed.