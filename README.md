# Golang Network Port Scanner [![Travis-CI](https://api.travis-ci.org/P-A-R-U-S/Golang-Network-Scanner.svg?branch=master)](https://travis-ci.org/P-A-R-U-S/Golang-Network-Scanner) [![License](https://img.shields.io/dub/l/vibe-d.svg)](https://opensource.org/licenses/MIT)

Simple command line tool to scan network ports. Command line tool was done as part of technical interview and as example for article on [HabraHabr.ru](https://habrahabr.ru/post/351574/).

The main requirement for the tool to accept individual IP, range of IPs in regular format or CIDR (Classless Inter-Domain Routing). The utility are free to use or change.

There was no requirement to build like a package, but you can easily converted it. Enjoy coding.

## Example 

```
$ ./netscanner --ip 10.0.1.1-10.0.1.11,10.0.1.12/32 --p 80 --pc tcp,udp --t 3000

Parameters:
    NAME:
       NetScanner - Network IP addresses and ports scanner
    
    USAGE:
       netscanner [global options] command [command options] [arguments...]
    
    AUTHOR:
       Valentyn Ponomarenko <bootloader@list.ru>
    
    COMMANDS:
         help, h  Shows a list of commands or help for one command
    
    GLOBAL OPTIONS:
       --ip value                    IP range, e.g --ip 127.0.0.1/12, 10.0.1.1-10.0.1.12
       --protocol value, --pc value  protocol for IP(s) scan, e.g --pc tcp (default: "tcp,udp")
       --port value, -p value        port range to scan, e.g --port 1-200 (default: "1-65535")
       --timeout value, -t value     timeOut n milliseconds, e.g. --t 3000 or --t 2s or --t 3000ms (default: "2000")
       --help, -h                    show help
       --version, -v                 print the version


Output:
    ......
    2018/03/19 23:40:20 scanning addr: tcp://10.0.1.1:138
    2018/03/19 23:40:20 scanning addr: tcp://10.0.1.1:139
    2018/03/19 23:40:20 tcp://10.0.1.1:139 is alive and reachable
    ......
```

## Contributing

We welcome pull requests, bug fixes and issue reports. 

Before proposing a change, please discuss your change by raising an issue.

## Authors

* **Valentyn Ponomarenko** - *Initial work* - [P-A-R-U-S](https://github.com/P-A-R-U-S)

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details