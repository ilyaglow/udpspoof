[![GoDoc](https://godoc.org/ilya.app/udpspoof?status.svg)](http://godoc.org/ilya.app/udpspoof)

About
-----

This is an experimental library that allows you to use arbitrary source
IP-address without gopacket or libpcap dependencies. The code is heavily based
on the [work](https://gist.github.com/chrisnc/0ff3d1c20cb6687454b0) by
@chrisnc.

Usage example
-------------

```go
package main

import "ilya.app/udpspoof"

func main() {
	conn, err := udpspoof.NewUDPConn("127.0.0.1:5000")
	if err != nil {
		log.Fatal(err)
	}

	_, err = conn.WriteAs(net.ParseIP("8.8.8.8"), []byte("Hello\n"))
	if err != nil {
		log.Fatal(err)
	}
}
```
