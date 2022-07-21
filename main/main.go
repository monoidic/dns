package main

import (
	"fmt"

	"github.com/monoidic/dns"
)

func main() {
	c := dns.Client{}
	msg := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Opcode:           dns.OpcodeQuery,
			RecursionDesired: true,
			Rcode:            dns.RcodeSuccess,
			Id:               dns.Id(),
		},
		Question: []dns.Question{{
			Qclass: dns.ClassINET,
			Qtype:  dns.TypeAMTRELAY,
			Name:   "amtrelay.dns.netmeister.org.",
		}},
	}

	res, _, err := c.Exchange(&msg, "127.0.0.53:53")
	if err == nil && len(res.Answer) > 0 {
		rr := res.Answer[0].(*dns.AMTRELAY)
		fmt.Printf("%v\n%[1]#v\n", rr)
	} else {
		fmt.Printf("err: %v\n", err)
	}
}
