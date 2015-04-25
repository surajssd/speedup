# speedup
Speedup your internet speed on your LAN.

This python script will increase your internet speed by eliminating access to default gateway for anyone on your *LAN*. This script regularly checks which all hosts are online using *nmap*. After that it stops anyone from getting access to default gateway by doing an **arpspoofing attack**. So basically what happens is everyone on the LAN is in **Denial of Service(DOS)** except you. Thats how you can use up all of the bandwidth for yourself.

This script also has facility of **excluding ip addresses** those whom you do not wanna block access. Also you can specify the **interface** on which you are connected to. By default the interface is 'eth0'.

## Dependencies Installation
### Ubuntu
```
sudo apt-get install nmap
sudo apt-get install dsniff
```
### Fedora
```
```
### Python
```
sudo pip install python-nmap
```

### Usage
```
Usage: sudo python speedup.py

Options:
  -h, --help  show this help message and exit
  -i IFACE    network interface you wanna speed up
  -e EXCLUDE  specify ip[s] to be excluded seperated by comma

```
