package main

import (
	"testing"
	"fmt"
)

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

	contains := func (arr *[]string, str string) bool {
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

		if !(contains(&psc, "tcp") || contains(&psc, "udp")) {
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
