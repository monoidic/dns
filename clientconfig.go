package dns

import (
	"bufio"
	"io"
	"os"
	"strconv"
	"strings"
)

// ClientConfig wraps the contents of the /etc/resolv.conf file.
type ClientConfig struct {
	Servers  []string // servers to use
	Search   []Name   // suffixes to append to local name
	Port     string   // what port to use
	Ndots    int      // number of dots in name to trigger absolute lookup
	Timeout  int      // seconds before giving up on packet
	Attempts int      // lost packets before giving up on server, not used in the package dns
}

// ClientConfigFromFile parses a resolv.conf(5) like file and returns
// a *ClientConfig.
func ClientConfigFromFile(resolvconf string) (*ClientConfig, error) {
	file, err := os.Open(resolvconf)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return ClientConfigFromReader(file)
}

// ClientConfigFromReader works like ClientConfigFromFile but takes an io.Reader as argument
func ClientConfigFromReader(resolvconf io.Reader) (*ClientConfig, error) {
	c := new(ClientConfig)
	scanner := bufio.NewScanner(resolvconf)
	c.Port = "53"
	c.Ndots = 1
	c.Timeout = 5
	c.Attempts = 2

	for scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return nil, err
		}
		line := scanner.Text()
		f := strings.Fields(line)
		if len(f) < 1 {
			continue
		}
		switch f[0] {
		case "nameserver": // add one name server
			if len(f) > 1 {
				// One more check: make sure server name is
				// just an IP address.  Otherwise we need DNS
				// to look it up.
				name := f[1]
				c.Servers = append(c.Servers, name)
			}

		case "domain": // set search path to just this domain
			if len(f) > 1 {
				domain, err := NameFromString(Fqdn(f[1]))
				if err != nil {
					return nil, err
				}
				c.Search = []Name{domain}
			}
		case "search": // set search path to given servers
			names := make([]Name, len(f[1:]))
			for i, v := range f[1:] {
				var err error
				names[i], err = NameFromString(Fqdn(v))
				if err != nil {
					return nil, err
				}
			}
			c.Search = names

		case "options": // magic options
			for _, s := range f[1:] {
				switch {
				case len(s) >= 6 && s[:6] == "ndots:":
					n, _ := strconv.Atoi(s[6:])
					if n < 0 {
						n = 0
					} else if n > 15 {
						n = 15
					}
					c.Ndots = n
				case len(s) >= 8 && s[:8] == "timeout:":
					n, _ := strconv.Atoi(s[8:])
					if n < 1 {
						n = 1
					}
					c.Timeout = n
				case len(s) >= 9 && s[:9] == "attempts:":
					n, _ := strconv.Atoi(s[9:])
					if n < 1 {
						n = 1
					}
					c.Attempts = n
				case s == "rotate":
					/* not imp */
				}
			}
		}
	}
	return c, nil
}

// NameList returns all of the names that should be queried based on the
// config. It is based off of go's net/dns name building, but it does not
// check the length of the resulting names.
func (c *ClientConfig) NameList(nameS string) []Name {
	// if this domain is already fully qualified, no append needed.
	if IsFqdn(nameS) {
		var ret []Name
		if name, err := NameFromString(nameS); err == nil {
			ret = append(ret, name)
		}
		return ret
	}

	name, err := NameFromString(Fqdn(nameS))
	if err != nil {
		return nil
	}

	// Check to see if the name has more labels than Ndots. Do this before making
	// the domain fully qualified.
	hasNdots := name.CountLabel() > c.Ndots
	// Make the domain fully qualified.

	// Make a list of names based off search.
	var names []Name

	// If name has enough dots, try that first.
	if hasNdots {
		names = append(names, name)
	}
	for _, s := range c.Search {
		concated, err := name.Concat(s)
		if err == nil {
			names = append(names, concated)
		}
	}
	// If we didn't have enough dots, try after suffixes.
	if !hasNdots {
		names = append(names, name)
	}
	return names
}
