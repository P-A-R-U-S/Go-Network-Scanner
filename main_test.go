package main

import (
	"testing"
	"fmt"
	"strings"
	"time"
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
		t.Errorf("port are not parsed correctly: expected: %d, but actual: %d", 1, portStart )
	}

	if portEnd != 65535 {
		t.Errorf("port are not parsed correctly: expected: %d, but actual: %d", 65535, portStart )
	}
}

func Test_Should_parse_successfully_if_only_one_port_parameter_passed_as_argument(t *testing.T) {
	portStart, portEnd, err := getPorts("3345")

	if err != nil {
		t.Fail()
	}

	if portStart != 3345 {
		t.Errorf("Port are not parsed correctly: expected: %d, but actual: %d", 3345, portStart )
	}

	if portEnd != 65535 {
		t.Errorf("Port are not parsed correctly: expected: %d, but actual: %d", 65535, portStart )
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

func Test_Should_parse_IPv4_Range_to_CIDR_Range_successfully(t *testing.T) {
	testDatas := []struct {
		ipStart string
		ipEnd 	string
		CIDRs	[]string
	}{
		//{ipStart:"10.0.1.1", ipEnd:"10.0.1.1", CIDRs: []string{"10.0.1.1/32"}},
		{ipStart:"216.58.192.12", ipEnd:"216.58.192.206", CIDRs: []string{
																			"216.58.192.12/30",
																			"216.58.192.16/28",
																			"216.58.192.32/27",
																			"216.58.192.64/26",
																			"216.58.192.128/26",
																			"216.58.192.192/29",
																			"216.58.192.200/30",
																			"216.58.192.204/31",
																			"216.58.192.206/32",
																		}},
		{ipStart:"127.0.0.1", ipEnd:"127.0.0.1", CIDRs: []string{"127.0.0.1/32"}},
		{ipStart:"4.2.2.2", ipEnd:"4.8.1.3", CIDRs: []string{	"4.2.2.2/31",
																"4.2.2.4/30",
																"4.2.2.8/29",
																"4.2.2.16/28",
																"4.2.2.32/27",
																"4.2.2.64/26",
																"4.2.2.128/25",
																"4.2.3.0/24",
																"4.2.4.0/22",
																"4.2.8.0/21",
																"4.2.16.0/20",
																"4.2.32.0/19",
																"4.2.64.0/18",
																"4.2.128.0/17",
																"4.3.0.0/16",
																"4.4.0.0/14",
																"4.8.0.0/24",
																"4.8.1.0/30",
															}},
		{ipStart:"128.105.12.11", ipEnd:"128.105.39.11", CIDRs: []string{
																		"128.105.12.11/32",
																		"128.105.12.12/30",
																		"128.105.12.16/28",
																		"128.105.12.32/27",
																		"128.105.12.64/26",
																		"128.105.12.128/25",
																		"128.105.13.0/24",
																		"128.105.14.0/23",
																		"128.105.16.0/20",
																		"128.105.32.0/22",
																		"128.105.36.0/23",
																		"128.105.38.0/24",
																		"128.105.39.0/29",
																		"128.105.39.8/30",
																	}},
		{ipStart:"84.200.70.40", ipEnd:"85.200.70.40", CIDRs: []string{
																		"84.200.70.40/29",
																		"84.200.70.48/28",
																		"84.200.70.64/26",
																		"84.200.70.128/25",
																		"84.200.71.0/24",
																		"84.200.72.0/21",
																		"84.200.80.0/20",
																		"84.200.96.0/19",
																		"84.200.128.0/17",
																		"84.201.0.0/16",
																		"84.202.0.0/15",
																		"84.204.0.0/14",
																		"84.208.0.0/12",
																		"84.224.0.0/11",
																		"85.0.0.0/9",
																		"85.128.0.0/10",
																		"85.192.0.0/13",
																		"85.200.0.0/18",
																		"85.200.64.0/22",
																		"85.200.68.0/23",
																		"85.200.70.0/27",
																		"85.200.70.32/29",
																		"85.200.70.40/32",
																	}},
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
		CIDRs, err := iPv4RangeToCIDRRange(testData.ipStart, testData.ipEnd)

		if err != nil {
			t.Errorf("incorrect IP range (%s - %s)", testData.ipStart, testData.ipEnd)
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

func Test_Should_parse_CIDR_Range_to_IPv4_Range_successfully(t *testing.T) {
	testDatas := []struct {
		ipStart string
		ipEnd   string
		CIDRs   []string
	}{
		{ipStart: "216.58.192.12", ipEnd: "216.58.192.23", CIDRs: []string{"216.58.192.12/30","216.58.192.16/29"}},

		{ipStart: "10.0.1.1", ipEnd: "10.0.1.1", CIDRs: []string{"10.0.1.1/32"}},
		{ipStart: "192.168.11.0", ipEnd: "192.168.11.7", CIDRs: []string{"192.168.11.0/29"}},
		{ipStart: "192.168.11.0", ipEnd: "192.168.11.7", CIDRs: []string{"192.168.11.0/29"}},
		{ipStart:"216.58.192.12", ipEnd:"216.58.192.206", CIDRs: []string{
			"216.58.192.12/30",
			"216.58.192.16/28",
			"216.58.192.32/27",
			"216.58.192.64/26",
			"216.58.192.128/26",
			"216.58.192.192/29",
			"216.58.192.200/30",
			"216.58.192.204/31",
			"216.58.192.206/32",
		}},
		{ipStart:"216.58.192.12", ipEnd:"216.58.192.206", CIDRs: []string{
			"216.58.192.32/27",
			"216.58.192.192/29",
			"216.58.192.200/30",
			"216.58.192.206/32",
			"216.58.192.128/26",
			"216.58.192.16/28",
			"216.58.192.204/31",
			"216.58.192.64/26",
			"216.58.192.12/30",
		}},
		{ipStart: "127.0.0.1", ipEnd: "127.0.0.1", CIDRs: []string{"127.0.0.1/32"}},
		{ipStart:"4.2.2.2", ipEnd:"4.8.1.3", CIDRs: []string{
			"4.2.2.2/31",
			"4.2.2.4/30",
			"4.2.2.8/29",
			"4.2.2.16/28",
			"4.2.2.32/27",
			"4.2.2.64/26",
			"4.2.2.128/25",
			"4.2.3.0/24",
			"4.2.4.0/22",
			"4.2.8.0/21",
			"4.2.16.0/20",
			"4.2.32.0/19",
			"4.2.64.0/18",
			"4.2.128.0/17",
			"4.3.0.0/16",
			"4.4.0.0/14",
			"4.8.0.0/24",
			"4.8.1.0/30",
		}},
		{ipStart:"128.105.12.11", ipEnd:"128.105.39.11", CIDRs: []string{
			"128.105.12.11/32",
			"128.105.12.12/30",
			"128.105.12.16/28",
			"128.105.12.32/27",
			"128.105.12.64/26",
			"128.105.12.128/25",
			"128.105.13.0/24",
			"128.105.14.0/23",
			"128.105.16.0/20",
			"128.105.32.0/22",
			"128.105.36.0/23",
			"128.105.38.0/24",
			"128.105.39.0/29",
			"128.105.39.8/30",
		}},
		{ipStart:"84.200.70.40", ipEnd:"85.200.70.40", CIDRs: []string{
			"84.200.70.40/29",
			"84.200.70.48/28",
			"84.200.70.64/26",
			"84.200.70.128/25",
			"84.200.71.0/24",
			"84.200.72.0/21",
			"84.200.80.0/20",
			"84.200.96.0/19",
			"84.200.128.0/17",
			"84.201.0.0/16",
			"84.202.0.0/15",
			"84.204.0.0/14",
			"84.208.0.0/12",
			"84.224.0.0/11",
			"85.0.0.0/9",
			"85.128.0.0/10",
			"85.192.0.0/13",
			"85.200.0.0/18",
			"85.200.64.0/22",
			"85.200.68.0/23",
			"85.200.70.0/27",
			"85.200.70.32/29",
			"85.200.70.40/32",
		}},
	}

	for _, testData := range testDatas {

		var ipStart string
		var ipEnd string

		ipS, ipE, err := CIDRRangeToIPv4Range(testData.CIDRs)

		if err != nil {
			t.Errorf("error to parse CIDR:%s", strings.Join(testData.CIDRs, ","))
		}

		if len(ipStart) == 0 || iPv4ToUint32(ipS) < iPv4ToUint32(ipStart) {
			ipStart = ipS
		}

		if len(ipEnd) == 0 || iPv4ToUint32(ipE) > iPv4ToUint32(ipEnd) {
			ipEnd = ipE
		}

		if testData.ipStart != ipStart {
			t.Errorf("start IP: %s not match to IP: %s for CIDR: %s", ipStart, testData.ipStart, strings.Join(testData.CIDRs, ","))
		}

		if testData.ipEnd != ipEnd {
			t.Errorf("end IP: %s not match to IP: %s for CIDR: %s", ipEnd, testData.ipEnd, strings.Join(testData.CIDRs, ","))
		}
	}
}

func Test_Should_get_IP_parameter_successfully(t *testing.T) {
	testDatas := []struct {
		parameter string
		CIDRs     []string
	}{
		{parameter: "216.58.192.12-216.58.192.23", CIDRs: []string{"216.58.192.12/30","216.58.192.16/29"}},

		{parameter: "10.0.1.1-10.0.1.1", CIDRs: []string{"10.0.1.1/32"}},
		{parameter: "192.168.11.0-192.168.11.7", CIDRs: []string{"192.168.11.0/29"}},
		{parameter: "192.168.11.0-192.168.11.7", CIDRs: []string{"192.168.11.0/29"}},
		{parameter:"216.58.192.12-216.58.192.206", CIDRs: []string{
			"216.58.192.12/30",
			"216.58.192.16/28",
			"216.58.192.32/27",
			"216.58.192.64/26",
			"216.58.192.128/26",
			"216.58.192.192/29",
			"216.58.192.200/30",
			"216.58.192.204/31",
			"216.58.192.206/32",
		}},
		{parameter:"216.58.192.12-216.58.192.206", CIDRs: []string{
			"216.58.192.32/27",
			"216.58.192.192/29",
			"216.58.192.200/30",
			"216.58.192.206/32",
			"216.58.192.128/26",
			"216.58.192.16/28",
			"216.58.192.204/31",
			"216.58.192.64/26",
			"216.58.192.12/30",
		}},
		{parameter: "127.0.0.1-127.0.0.1", CIDRs: []string{"127.0.0.1/32"}},
		{parameter:"4.2.2.2-4.8.1.3", CIDRs: []string{
			"4.2.2.2/31",
			"4.2.2.4/30",
			"4.2.2.8/29",
			"4.2.2.16/28",
			"4.2.2.32/27",
			"4.2.2.64/26",
			"4.2.2.128/25",
			"4.2.3.0/24",
			"4.2.4.0/22",
			"4.2.8.0/21",
			"4.2.16.0/20",
			"4.2.32.0/19",
			"4.2.64.0/18",
			"4.2.128.0/17",
			"4.3.0.0/16",
			"4.4.0.0/14",
			"4.8.0.0/24",
			"4.8.1.0/30",
		}},
		{parameter:"128.105.12.11-128.105.39.11", CIDRs: []string{
			"128.105.12.11/32",
			"128.105.12.12/30",
			"128.105.12.16/28",
			"128.105.12.32/27",
			"128.105.12.64/26",
			"128.105.12.128/25",
			"128.105.13.0/24",
			"128.105.14.0/23",
			"128.105.16.0/20",
			"128.105.32.0/22",
			"128.105.36.0/23",
			"128.105.38.0/24",
			"128.105.39.0/29",
			"128.105.39.8/30",
		}},
		{parameter:"84.200.70.40-85.200.70.40", CIDRs: []string{
			"84.200.70.40/29",
			"84.200.70.48/28",
			"84.200.70.64/26",
			"84.200.70.128/25",
			"84.200.71.0/24",
			"84.200.72.0/21",
			"84.200.80.0/20",
			"84.200.96.0/19",
			"84.200.128.0/17",
			"84.201.0.0/16",
			"84.202.0.0/15",
			"84.204.0.0/14",
			"84.208.0.0/12",
			"84.224.0.0/11",
			"85.0.0.0/9",
			"85.128.0.0/10",
			"85.192.0.0/13",
			"85.200.0.0/18",
			"85.200.64.0/22",
			"85.200.68.0/23",
			"85.200.70.0/27",
			"85.200.70.32/29",
			"85.200.70.40/32",
		}},
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
		CIDRs, err := getCIDRs(testData.parameter)

		if err != nil {
			t.Errorf("incorrect IP range (%s)", testData.parameter)
		}

		if len(CIDRs) != len(testData.CIDRs) {
			t.Errorf("incorrect number of CIDR address for IP range (%s)", testData.parameter)
		}

		for _, CIDR := range CIDRs {

			if !isContains(&testData.CIDRs, CIDR) {
				t.Errorf(" CIDR: %s not existing in IP range (%s)", CIDR, testData.parameter)
			}
		}
	}
}

func Test_Should_get_Timeout_parameter_successfully(t *testing.T) {
	testDatas := []struct {
		parameter string
		timeOut   time.Duration
	}{

		{parameter: "3000", timeOut: time.Millisecond * 3000 },
		{parameter: "2s", timeOut: time.Second * 2 },
		{parameter: "20ms", timeOut: time.Millisecond * 20 },
		{parameter: "30", timeOut: time.Millisecond * 30 },
		{parameter: "3m", timeOut: time.Minute * 3 },
	}

	for _, testData := range testDatas {
		timeOut, err := getTimeout(testData.parameter)

		if err != nil {
			t.Errorf("incorrect timeOut value (%s)", testData.parameter)
		}

		if timeOut != testData.timeOut {
			t.Errorf("timeOut parameter:(%s) parsed incorrectly: expected:(%s), but found:(%s)  ", testData.parameter, testData.timeOut, timeOut)
		}
	}
}

func Test_IPv4_to_Long(t *testing.T)  {

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

		res1 := iPv4ToUint32(v.iP)
		if res1 != v.Long {
			t.Errorf("long value for IP: %s is %d, but expected %d", v.iP, res1, v.Long)
		}
	}

}

func Test_Long_to_IPv4(t *testing.T)  {

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

		res1 := uInt32ToIPv4(v.Long)
		if res1 != v.iP {
			t.Errorf("long value for IP: %s is %s, but expected %d", v.iP, res1, v.Long)
		}
	}

}

func Test_Bitwise_Complement_Operator(t *testing.T) {

	testDatas := []struct {
		source      uint32
		bitWiseConverted uint32
	}{
		{0x00000000, 0xffffffff},
		{0x00000111, 0xfffffeee},
		{0x000fffff, 0xfff00000},
		{0x00008888, 0xffff7777},
		{0x22000022, 0xddffffdd},
	}

	for _,testData := range testDatas {

		result := ^testData.source
		if result != testData.bitWiseConverted {
			t.Errorf("failed for: source %d: exetected bitWise converted value: %d, but found: %d",
				testData.source,
				testData.bitWiseConverted,
				result	)
		}
	}
}
