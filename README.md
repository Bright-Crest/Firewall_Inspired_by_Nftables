# Firewall_Inspired_by_Nftables
A Linux module of implementing a firewall based on Netfilter and a corresponding program in user mode. This project is a group assignment of course "信息安全科技创新"

test cmd:

```
./NftFirewallUser add chain mytable ftchain -t filter -h input -p 0 -a accept
```