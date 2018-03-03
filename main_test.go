package main

import (
	"testing"
	"fmt"
	"strings"
	"strconv"
)

//

//Expecting error
func Test_Should_throw_error_when_port_parameter_not_contains_correct_value_for_ports(t *testing.T) {

	portParameterValues := [...]string{"@#@$@@" , "@#@$@@,123123", ",,,", ",","12$3,123123", "_,_", "_"}


	for _, portParameterValue := range portParameterValues {

		portStart, portEnd, err := getPorts(portParameterValue)

		if portStart != 1 {
			t.Errorf("Start Port are not parsed correctly: expected: %d, but actual: %d", 1, portStart )
		}

		if portEnd != 65535 {
			fmt.Errorf("failed with paramater: %s", portParameterValue)
			t.Errorf("End Port are not parsed correctly: expected: %d, but actual: %d", 65535, portEnd )
		}

		if err == nil {
			fmt.Errorf("failed with paramater: %s", portParameterValue)
			t.Fail()
		}
	}

}

func Test_Should_throw_error_when_protocol_parameter_not_contains_correct_value_for_ports(t *testing.T) {

	protocolParameterValues := [...]string{"tcp,udp,http", "https,http", ",,,", ",","12$3,454", "_,_", "_", "-1,1000"}

	isContains := func (arr *[]string, str string) bool {
		for _, a := range *arr {
			if a == str {
				return true
			}
		}
		return false
	}

	for _, v := range protocolParameterValues {

		psc, err := getProtocols(v)

		if err == nil {
			fmt.Errorf("failed with paramater: %s", v)
			t.Fail()
		}

		if !(isContains(&psc, "tcp") || isContains(&psc, "udp")) {
			t.Error("at least tpc or udp or both should be used as default protocol for network scan")
		}

	}

}


//Not expecting error
func Test_Should_not_throw_error_when_port_parameter_is_empty_string(t *testing.T) {

	portStart, portEnd, err := getPorts("")

	if err != nil {
		t.Fail()
	}

	if portStart != 1 {
		t.Errorf("Port are not parsed correctly: expected: %s, but actual: %s", 1, portStart )
	}

	if portEnd != 65535 {
		t.Errorf("Port are not parsed correctly: expected: %s, but actual: %s", 65535, portStart )
	}
}

func Test_Should_parse_successfully_if_only_one_port_parameter_passed_as_argument(t *testing.T) {
	portStart, portEnd, err := getPorts("3345")

	if err != nil {
		t.Fail()
	}

	if portStart != 3345 {
		t.Errorf("Port are not parsed correctly: expected: %s, but actual: %s", 3345, portStart )
	}

	if portEnd != 65535 {
		t.Errorf("Port are not parsed correctly: expected: %s, but actual: %s", 65535, portStart )
	}
}

func Test_Should_not_throw_error_when_protocol_parameter_is_empty_string(t *testing.T) {

	psc, err := getProtocols("")

	if err != nil {
		t.Fail()
	}

	contains := func (arr *[]string, str string) bool {
		for _, a := range *arr {
			if a == str {
				return true
			}
		}
		return false
	}

	if !(contains(&psc, "tcp") || contains(&psc, "udp")) {
		t.Error("at least tpc or udp or both should be used as default protocol for network scan")
	}

}

func Test_Should_parse_IP_to_CIDR_successfully(t *testing.T) {
	testDatas := []struct {
		ipStart string
		ipEnd 	string
		CIDRs	[]string
	}{
		{ipStart:"10.0.1.1", ipEnd:"10.0.1.1", CIDRs: []string{"10.0.1.1/32"}},
		//{ipStart:"216.58.192.12", ipEnd:"216.58.192.206", CIDRs: []string{
		//																	"216.58.192.12/30",
		//																	"216.58.192.16/28",
		//																	"216.58.192.32/27",
		//																	"216.58.192.64/26",
		//																	"216.58.192.128/26",
		//																	"216.58.192.192/29",
		//																	"216.58.192.200/30",
		//																	"216.58.192.204/31",
		//																	"216.58.192.206/32",
		//																}},
		//{ipStart:"127.0.0.1", ipEnd:"127.0.0.1", CIDRs: []string{"127.0.0.1/32"}},
	}


	isContains := func (arr *[]string, str string) bool {
		for _, a := range *arr {
			if a == str {
				return true
			}
		}
		return false
	}

	for _, testData := range testDatas {
		CIDRs, err := IPRangeToCIDR(testData.ipStart, testData.ipEnd)

		if err != nil {
			t.Errorf("incorect IP range (%s - %s)", testData.ipStart, testData.ipEnd)
		}

		if len(CIDRs) != len(testData.CIDRs) {
			t.Errorf("incorrect number of CIDR address for IP range (%s - %s)", testData.ipStart, testData.ipEnd)
		}

		for _, CIDR := range CIDRs {

			if !isContains(&testData.CIDRs, CIDR) {
				t.Errorf(" CIDR: %s not existing in IP range (%s - %s)", CIDR, testData.ipStart, testData.ipEnd)
			}
		}
	}
}

func Test_IP_to_Long(t *testing.T)  {

	iPToUint32 := func(ip string ) uint32 {

		ipOctets := [4]uint64{}

		for i, v := range strings.SplitN(ip,".", 4) {
			ipOctets[i], _  = strconv.ParseUint(v, 10, 32)
		}

		result := (ipOctets[0] << 24) + (ipOctets[1] << 16) + (ipOctets[2] << 8) + ipOctets[3]

		return uint32(result)
	}


	testDatas := []struct {
		iP string
		Long uint32
	}{
		{"10.0.1.1", 167772417},
		{"216.58.192.12", 3627728908},
		{"127.0.0.1", 2130706433},
		{"192.168.0.1", 3232235521 },
		{"4.2.2.2", 67240450},
		{"128.105.39.11", 2154374923},
		{"192.16.184.0", 3222321152},
		{"208.67.222.222", 3494108894},
		{"156.154.70.1", 2627356161},
		{"84.200.70.40", 1422411304},
		{"199.85.126.10", 3344268810},
		{"209.88.198.133", 3512256133},
		{"50.116.23.21", 846468885},

	}

	for _,v := range testDatas {

		res1 := iPToUint32(v.iP)
		if res1 != v.Long {
			t.Errorf("long value for IP: %s is %d, but expected %d", v.iP, res1, v.Long)
		}
	}

}

func Test_Long_to_IP(t *testing.T)  {

	uInt32ToIP := func(iPuInt32 uint32) (iP string) {
		iP =  fmt.Sprintf ("%d.%d.%d.%d",
			iPuInt32 >> 24,
			(iPuInt32 & 0x00FFFFFF)>> 16,
			(iPuInt32 & 0x0000FFFF) >> 8,
			iPuInt32 & 0x000000FF)
		return iP
	}


	testDatas := []struct {
		iP string
		Long uint32
	}{
		{"10.0.1.1", 167772417},
		{"216.58.192.12", 3627728908},
		{"127.0.0.1", 2130706433},
		{"192.168.0.1", 3232235521 },
		{"4.2.2.2", 67240450},
		{"128.105.39.11", 2154374923},
		{"192.16.184.0", 3222321152},
		{"208.67.222.222", 3494108894},
		{"156.154.70.1", 2627356161},
		{"84.200.70.40", 1422411304},
		{"199.85.126.10", 3344268810},
		{"209.88.198.133", 3512256133},
		{"50.116.23.21", 846468885},

	}

	for _,v := range testDatas {

		res1 := uInt32ToIP(v.Long)
		if res1 != v.iP {
			t.Errorf("long value for IP: %s is %s, but expected %d", v.iP, res1, v.Long)
		}
	}

}