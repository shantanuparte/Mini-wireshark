# Mini-Wireshark

## Mini packet sniffer in Goooo...

A small cli based packet sniffer inspired by wireshark cause i got Blåhaj form hackclub(really). It does this thgough pcap go package and filters though BPF filter and prints each package, saves if you want in to file and can read it.



## Features

- Live capture of packages from any interface
- Filter by protocol, host and other stuff using BPF
- Save packages to capture.pcap(if you add -log flag)
- Reads saved .pcap file (use -jaw flag)
- Through cli itself

## Requirments

Minishark uses libpcap so install the devel first ╰‿╯

```
# Fedora
sudo dnf install libpcap-devel

# Debian/Ubuntu
sudo apt install libcap-dev
```

Run the program through `sudo` as it needs root access

## Build for yourself

Clone the repo ¯(ツ)/¯

```
git clone https://github.com/shantanuparte/Mini-wireshark.git
cd minishark
```

build it

```
go build -o minishark .
```

## Usage

You can also use ` sudo ./minishark --help`
It has 2 modes as capture and read

1. Sniff the packets

```
sudo ./minishark -list="any" -filter="tcp port 443" -pack_size=65535 -log=true -dur=10
```

here

- list: Netowrk interface you want ex. wlp2s0, eth0 (default any)
- filter: BPF filter(See the table of filters)
- pack_size: Max bytes captures per packet(65535)
- log: Set true to save the info into capture.pcap file (default flase)
  -dur: Short for duration, how much seconds you wanna sniff (default runs until `Ctrl+C`)

2. Read: Sohw the packets saved in file
```
sudo ./minishark -jaw=true
```

- jaw: Short for nothing it just sounds familiar with something realted to shark so i addded it. reads the packets saved in file

Note: Every new `log-true` overwirtes the file

## Filters


| What you want | Filter |
|---|---|
| Only TCP | `tcp` |
| Only UDP | `udp` |
| TCP or UDP | `tcp or udp` |
| Port 80 (TCP and UDP) | `port 80` |
| TCP port 80 only | `tcp port 80` |
| HTTP and HTTPS | `port 80 or port 443` |
| DNS | `udp port 53` |
| One host (any direction) | `host 8.8.8.8` |
| Only from a host | `src host 10.0.0.5` |
| Only to a host | `dst host 10.0.0.5` |
| Host and port | `host 8.8.8.8 and port 53` |
| Everything except SSH | `not port 22` |
| Ping | `icmp` |
| Port range | `portrange 8000-9000` |


Rules for filter:
- Combine conditions with `and`,`or`,`not` and use parenthese when mixing
- Put the whole filter in quotes
- like use `(tcp or udp) and port 80` not `tcp and udp port 80`






