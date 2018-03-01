package main

import (
	//"log"
	"os"

	"github.com/urfave/cli"
	"strings"
	"strconv"
	"Golang-Errors-Helper"
	"net"
	"fmt"
)

// VERSION indicates which version of the binary is running.
var VERSION string

// GITCOMMIT indicates which git hash the binary was built off of
var GITCOMMIT string

var (
	ipStart net.IPAddr
	portStart, portEnd int
	protocols []string
)

func defaultInit(c *cli.Context) error {
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




	//a.Action = func(c *cli.Context) error {
	//	var err error
	//
	//	if len(c.Args()) == 0 {
	//		fmt.Print("ll entire network will be scanned for all open IPs and ports.")
	//		cli.ShowAppHelp(c)
	//	}
	//
	//	if c.IsSet("protocol") || c.IsSet("pc") {
	//		protocols, err = getProtocols(c.String("protocol"))
	//		if err != nil {
	//			log.Fatalf("not able to parse 'protocol' parameter value: %s. Following port value would be used: %d,%d",
	//				err, portStart, portEnd)
	//		}
	//	}
	//
	//	if c.IsSet("port") || c.IsSet("p") {
	//		portStart, portEnd, err = getPorts(c.String("port"))
	//		if err != nil {
	//			log.Fatalf("not able to parse 'port' parameter value: %s", err)
	//		}
	//	}
	//
	//	err = a.Run(os.Args)
	//	if err != nil {
	//		log.Fatal(err)
	//	}
	//
	//	return nil
	//}

	a.Run(os.Args)
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

