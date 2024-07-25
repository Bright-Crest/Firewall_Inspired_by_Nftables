# Firewall_Inspired_by_Nftables
A Linux module of implementing a firewall based on Netfilter and a corresponding program in user mode. This project is a group assignment of course "信息安全科技创新".

## Build

First make sure that your directory is the root directory of this project, of cousre.

To build the **kernel** module, change directory to ./kernel where Makefile is located.

1. `make` - build the kernel module
2. `make install` - install the kernel module and insert the module. The default location is /lib/modules/<kernel_release>/updates/. You may need to add `sudo`.
3. `make clean` - clean all the files generated during `make` only. 
4. `make help` - show help info.

To build the **user** program, change directory to ./user first where CMakeLists.txt is located. Then do the following commands to build.

```
cmake -S. -Bbuild
cd build
cmake --build .
```

Finally, you can run the program NftFirewallUser in the build directory.


## Test

test cmd:

```
./NftFirewallUser add chain mytable ftchain -t filter -h input -p 0 -a accept
./NftFirewallUser add rule mytable ftchain -r rule1 -p tcp -x 202.89.233.100 -y 192.168.193.136 -m 65535 -n 65535 -a deny
./NftFirewallUser add rule mytable ftchain -r rule2 -p tcp -y 202.89.233.100 -x 192.168.193.136 -m 65535 -n 65535 -a deny
```
