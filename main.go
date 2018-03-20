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
	"math"
	"regexp"
)

// VERSION indicates which version of the binary is running.
var VERSION string

// GITCOMMIT indicates which git hash the binary was built off of
var GITCOMMIT string

var (
	CIDRs []string
	portStart =1
	portEnd = 65535
	protocols = []string{"tcp","udp"}
	timeout = time.Microsecond * 2000
	wg sync.WaitGroup
)

func main() {

	a := cli.NewApp()
	a.Name = "NetScanner"
	a.Usage = "Network IP addresses and ports scanner"
	a.Author = "Valentyn Ponomarenko"
	a.Version = VERSION
	a.Email = "bootloader@list.ru"

	a.Flags = []cli.Flag {
		cli.StringFlag{
			Name:  "ip",
			Usage: "protocol for IP(s) scan, e.g --ip 127.0.0.1/12, 10.0.1.1-10.0.1.12",
		},
		cli.StringFlag{
			Name:  "protocol, pc",
			Value: "tcp,udp",
			Usage: "protocol for IP(s) scan, e.g ",
		},
		cli.StringFlag{
			Name:  "port, p",
			Value: "1-65535 or just start port 1000, e.g --port 1-200",
			Usage: "port range to scan",
		},
		cli.StringFlag{
			Name:  "timeout, t",
			Value: "in milliseconds, by default: 2000 msec(2 sec), e.g. --t 3000 or --t 2s or --t 3000ms",
			Usage: "timeOut",
		},
	}


	a.Action = func(c *cli.Context) error {
		var err error

		if len(c.Args()) == 0 {
			cli.ShowAppHelp(c)
		}

		if c.IsSet("ip") {
			CIDRs, err = getCIDRs(c.String("ip"))
			if err != nil {
				log.Fatalf("not able to parse 'ips' parameter value: %s.", err)
			}
		}

		if c.IsSet("t") || c.IsSet("timeout"){
			timeout, err = getTimeout(c.String("t"))
			if err != nil {
				log.Fatalf("not able to parse 'timeout' parameter value: %s.", err)
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

		//Scan CIDR address
		for _, cidr := range CIDRs {
			scan(cidr)
		}

		return nil
	}

	err := a.Run(os.Args)

	if err != nil {
		log.Fatal(err)
	}
}

func scan(cidr string) (err error) {

	var ip net.IP
	var ipNet *net.IPNet

	var incIP = func (ip net.IP) {
		for j := len(ip) - 1; j >= 0; j-- {
			ip[j]++
			if ip[j] > 0 {
				break
			}
		}
	}

	ip, ipNet, err = net.ParseCIDR(cidr)

	if err != nil {
		log.Printf("CIDR address not in correct format %s", err)
		return  err
	}


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

//Convert IPv4 to uint32
func iPv4ToUint32(iPv4 string ) uint32 {

	ipOctets := [4]uint64{}

	for i, v := range strings.SplitN(iPv4,".", 4) {
		ipOctets[i], _  = strconv.ParseUint(v, 10, 32)
	}

	result := (ipOctets[0] << 24) | (ipOctets[1] << 16) | (ipOctets[2] << 8) | ipOctets[3]

	return uint32(result)
}

//Convert uint32 to IP
func uInt32ToIPv4(iPuInt32 uint32) (iP string) {
	iP =  fmt.Sprintf ("%d.%d.%d.%d",
		iPuInt32 >> 24,
		(iPuInt32 & 0x00FFFFFF)>> 16,
		(iPuInt32 & 0x0000FFFF) >> 8,
		iPuInt32 & 0x000000FF)
	return iP
}

// Convert IPv4 range into CIDR
func iPv4RangeToCIDRRange(ipStart string, ipEnd string) (cidrs []string, err error) {

	cidr2mask := []uint32{
		0x00000000, 0x80000000, 0xC0000000,
		0xE0000000, 0xF0000000, 0xF8000000,
		0xFC000000, 0xFE000000, 0xFF000000,
		0xFF800000, 0xFFC00000, 0xFFE00000,
		0xFFF00000, 0xFFF80000, 0xFFFC0000,
		0xFFFE0000, 0xFFFF0000, 0xFFFF8000,
		0xFFFFC000, 0xFFFFE000, 0xFFFFF000,
		0xFFFFF800, 0xFFFFFC00, 0xFFFFFE00,
		0xFFFFFF00, 0xFFFFFF80, 0xFFFFFFC0,
		0xFFFFFFE0, 0xFFFFFFF0, 0xFFFFFFF8,
		0xFFFFFFFC, 0xFFFFFFFE, 0xFFFFFFFF,
	}

	ipStartUint32 := iPv4ToUint32(ipStart)
	ipEndUint32 := iPv4ToUint32(ipEnd)

	if ipStartUint32 > ipEndUint32 {
		log.Fatalf("start IP:%s must be less than end IP:%s", ipStart, ipEnd)
	}

	for ipEndUint32 >= ipStartUint32 {
		maxSize := 32
		for maxSize > 0 {

			maskedBase := ipStartUint32 & cidr2mask[maxSize - 1]

			if maskedBase != ipStartUint32 {
				break
			}
			maxSize--

		}

		x := math.Log(float64(ipEndUint32 - ipStartUint32 + 1)) / math.Log(2)
		maxDiff := 32 - int(math.Floor(x))
		if maxSize < maxDiff {
			maxSize = maxDiff
		}

		cidrs = append(cidrs,  uInt32ToIPv4(ipStartUint32) + "/" +  strconv.Itoa(maxSize))

		ipStartUint32 += uint32(math.Exp2(float64(32 - maxSize)))
	}

	return cidrs, err
}

// Convert CIDR to IPv4 range
func CIDRRangeToIPv4Range(cidrs []string) (ipStart string, ipEnd string, err error) {

	var ip uint32        // ip address

	var ipS uint32		 // Start IP address range
	var ipE uint32 		 // End IP address range

	for _, CIDR := range cidrs {

		cidrParts := strings.Split(CIDR, "/")

		ip = iPv4ToUint32(cidrParts[0])
		bits, _ := strconv.ParseUint(cidrParts[1], 10, 32)

		if ipS == 0 || ipS > ip {
			ipS = ip
		}

		ip = ip | (0xFFFFFFFF >> bits)

		if ipE < ip {
			ipE = ip
		}

	}

	ipStart = uInt32ToIPv4(ipS)
	ipEnd = uInt32ToIPv4(ipE)

	return ipStart, ipEnd, err
}

// Parse 'ips' parameter into the array of CDIR (https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing)
func getCIDRs(ipsParameter string)  (cidrs []string, err error) {

	paramParts := strings.Split(ipsParameter, ",")

	var cidrRegEx = regexp.MustCompile(`^([0-9]{1,3}\.){3}[0-9]{1,3}?$`)

	for _, v := range paramParts {
		paramParts :=  strings.TrimSpace(v)

		if cidrRegEx.MatchString(paramParts) {
			cidrs = append(cidrs, paramParts)
			continue
		}

		ipParamParts := strings.Split(paramParts, "-")

		ipStart := strings.TrimSpace(ipParamParts[0])
		ipEnd := ipStart
		if len(ipParamParts) >= 1 {
			ipEnd = strings.TrimSpace(ipParamParts[1])
		}

		paramPartsCidrs, err := iPv4RangeToCIDRRange(ipStart, ipEnd)

		if err != nil {
			fmt.Errorf("enable to parse IP range: %s - %s", ipStart, ipEnd)
		}

		cidrs = append(cidrs, paramPartsCidrs...)
	}

	return cidrs, err
}

// Parse 'port, p' parameter
func getPorts(portsParameter string) (begin int, end int, err error) {

	const minPort = 1
	const maxPort = 65535

	begin = minPort
	end = maxPort

	if len(portsParameter) == 0 {
		return minPort, maxPort, nil
	}

	parsedPorts := strings.Split(portsParameter, "-")

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
func getProtocols(protocolParameter string) ([]string, error) {

	if len(protocolParameter) == 0 {
		return []string{"tcp", "udp"}, nil
	}

	var pcs []string
	var pcsIgnored []string

	for _, v := range strings.Split(protocolParameter, ",") {

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

// Parse 'protocol, pc' parameter
func getTimeout(timeOutParameter string) (timeOut time.Duration, err error) {

	switch {
	case strings.HasSuffix(timeOutParameter, "ms"):
		timeOut, err = time.ParseDuration( timeOutParameter)
	case strings.HasSuffix(timeOutParameter, "s"):
		timeOut, err = time.ParseDuration( timeOutParameter)
	case strings.HasSuffix(timeOutParameter, "m"):
		timeOut, err = time.ParseDuration( timeOutParameter)
	default:
		timeOut, err = time.ParseDuration( timeOutParameter + "ms")
	}

	return timeOut, err
}


