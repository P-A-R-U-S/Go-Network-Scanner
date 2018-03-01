package main

import (
	"log"
	"os"
	"errors"
	"github.com/urfave/cli"
	"strings"
	"strconv"
	"net"
	"fmt"
	"time"
	"sync"
)

// VERSION indicates which version of the binary is running.
var VERSION string

// GITCOMMIT indicates which git hash the binary was built off of
var GITCOMMIT string

var (
	CIDRs []string
	portStart, portEnd int
	protocols []string
	wg sync.WaitGroup
)

func defaultInit(_ *cli.Context) error {
	portStart = 1
	portEnd = 65535
	protocols = []string{"tcp","udp"}

	return nil
}

func main() {
	a := cli.NewApp()
	a.Name = "NetScanner"
	a.Usage = "Network IP addresses and ports scanner"
	a.Author = "Valentyn Ponomarenko"
	a.Version = VERSION
	a.Email = "bootloader@list.ru"
	a.Before = defaultInit

	a.Flags = []cli.Flag {
		cli.StringFlag{
			Name:  "ips",
			Value: "127.0.0.1/12",
			Usage: "protocol for IP(s) scan",
		},
		cli.StringFlag{
			Name:  "protocol, pc",
			Value: "tcp,udp",
			Usage: "protocol for IP(s) scan",
		},
		cli.StringFlag{
			Name:  "port, p",
			Value: "1-65535 or just start port 1000",
			Usage: "port range to scan",
		},
	}


	a.Action = func(c *cli.Context) error {
		var err error

		if len(c.Args()) == 0 {
			fmt.Print("all entire network will be scanned for all open IPs and ports.")
			cli.ShowAppHelp(c)
		}

		if c.IsSet("ips") {
			CIDRs, err = getCIDRs(c.String("protocol"))
			if err != nil {
				log.Fatalf("not able to parse 'ips' parameter value: %s.", err)
			}
		}

		if c.IsSet("protocol") || c.IsSet("pc") {
			protocols, err = getProtocols(c.String("protocol"))
			if err != nil {
				log.Fatalf("not able to parse 'protocol' parameter value: %s. Following port value would be used: %d,%d",
					err, portStart, portEnd)
			}
		}

		if c.IsSet("port") || c.IsSet("p") {
			portStart, portEnd, err = getPorts(c.String("port"))
			if err != nil {
				log.Fatalf("not able to parse 'port' parameter value: %s", err)
			}
		}

		//Scan IP/CIDR address
		for _, cidr := range CIDRs {
			scanCDIR(cidr)
		}

		return nil
	}

	err := a.Run(os.Args)

	if err != nil {
		log.Fatal(err)
	}
}



func scanCDIR(cidr string) (err error) {

	var ip net.IP
	var ipNet *net.IPNet

	ip, ipNet, err = net.ParseCIDR(cidr)

	if err != nil {
		//ip = net.ParseIP(cidr)
		log.Printf("CIDR address not in correct format %s", err)
		return  err
	}

	timeout := time.Second * 2



	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); incIP(ip) {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()

			// ========
			for _, protocol := range protocols {
				for port := portStart; port <= portEnd; port++ {
					addr := fmt.Sprintf("%s:%d", ip, port)
					log.Printf("scanning addr: %s://%s\n", protocol, addr)

					c, e := net.DialTimeout(protocol, addr, timeout)
					if e == nil {
						c.Close()
						log.Printf("%s://%s is alive and reachable\n", protocol, addr)
					}

				}
			}
			// ========
		}(ip.String())
	}

	wg.Wait()

	return  err
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}


// Parse 'ips' parameter into the array of CDIR
// 		https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing
func getCIDRs(ips string)  (CIDRs []string, err error) {

	CIDRs = strings.Split(ips, ",")

	for i, v := range CIDRs {
		CIDRs[i] =  strings.TrimSpace(v)
	}

	return strings.Split(ips, ","), nil
}

// Parse 'port, p' parameter
func getPorts(ports string) (begin int, end int, err error) {

	const minPort = 1
	const maxPort = 65535

	begin = minPort
	end = maxPort

	if len(ports) == 0 {
		return minPort, maxPort, nil
	}

	parsedPorts := strings.Split(ports, ",")

	begin, err = strconv.Atoi(parsedPorts[0])

	if err != nil {
		begin = minPort
	} else if begin < minPort || begin >  maxPort{
		begin = minPort
		err = fmt.Errorf("port value: %d is out of ports range", begin)
	}

	if len(parsedPorts) > minPort {
		end, err = strconv.Atoi(parsedPorts[1])

		if err != nil {
			end = maxPort
		} else if end < minPort || end >  maxPort{
			end = maxPort
			err = fmt.Errorf("port value: %d is out of ports range", begin)
		}
	}

	if begin > end {
		return begin, end, fmt.Errorf("end port can not be greater than the beginning port: %d > %d", end, begin)
	}

	return begin, end, err
}

// Parse 'protocol, pc' parameter
func getProtocols(protocol string) ([]string, error) {

	if len(protocol) == 0 {
		return []string{"tcp", "udp"}, nil
	}

	var pcs []string
	var pcsIgnored []string

	for _, v := range strings.Split(protocol, ",") {

		v := strings.Trim(strings.ToLower(v),"")

		if v != "tcp" && v != "udp" {
			pcsIgnored = append(pcsIgnored, v)
			continue
		}

		pcs = append(pcs, v)
	}

	if len(pcs) == 0 {
		pcs = []string{"tcp", "udp"}
	}

	if len(pcsIgnored) > 0 {
		return pcs, errors.New("following protocol: '" + strings.Join(pcsIgnored,",")+ "' are not support and would be ignored.")
	}
	return pcs, nil
}

