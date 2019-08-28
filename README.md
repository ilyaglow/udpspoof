[![GoDoc](https://godoc.org/ilya.app/udpspoof?status.svg)](http://godoc.org/ilya.app/udpspoof)

About
-----

This is an experimental library that allows you to send packets with an
arbitrary source IP-address and doesn't depend on gopacket. The code is heavily
based on the [work](https://gist.github.com/chrisnc/0ff3d1c20cb6687454b0) by
@chrisnc.

It will truncate your payload if the maximum length is exceeded.

Usage example
-------------

```go
package main

import (
	"log"
	"net"

	"ilya.app/udpspoof"
)

func main() {
	conn, err := udpspoof.NewUDPConn("127.0.0.1:5000")
	if err != nil {
		log.Fatal(err)
	}

	_, err = conn.WriteAs(net.ParseIP("8.8.8.8"), uint16(53), []byte("Hello\n"))
	if err != nil {
		log.Fatal(err)
	}
}
```
