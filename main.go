package udpspoof

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"runtime"
	"strconv"
	"sync"

	"golang.org/x/sys/unix"
)

var (
	defaultSrcPort = uint16(54321)
	defaultSrcIP   = "127.0.0.1"
)

type iphdr struct {
	vhl   uint8
	tos   uint8
	iplen uint16
	id    uint16
	off   uint16
	ttl   uint8
	proto uint8
	csum  uint16
	src   [4]byte
	dst   [4]byte
}

type udphdr struct {
	src  uint16
	dst  uint16
	ulen uint16
	csum uint16
}

// pseudo header used for checksum calculation
type pseudohdr struct {
	ipsrc   [4]byte
	ipdst   [4]byte
	zero    uint8
	ipproto uint8
	plen    uint16
}

func checksum(buf []byte) uint16 {
	sum := uint32(0)

	for ; len(buf) >= 2; buf = buf[2:] {
		sum += uint32(buf[0])<<8 | uint32(buf[1])
	}
	if len(buf) > 0 {
		sum += uint32(buf[0]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	csum := ^uint16(sum)
	/*
	 * From RFC 768:
	 * If the computed checksum is zero, it is transmitted as all ones (the
	 * equivalent in one's complement arithmetic). An all zero transmitted
	 * checksum value means that the transmitter generated no checksum (for
	 * debugging or for higher level protocols that don't care).
	 */
	if csum == 0 {
		csum = 0xffff
	}
	return csum
}

func (h *iphdr) checksum() {
	h.csum = 0
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, h)
	h.csum = checksum(b.Bytes())
}

func (u *udphdr) checksum(ip *iphdr, payload []byte) {
	u.csum = 0
	phdr := pseudohdr{
		ipsrc:   ip.src,
		ipdst:   ip.dst,
		zero:    0,
		ipproto: ip.proto,
		plen:    u.ulen,
	}
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, &phdr)
	binary.Write(&b, binary.BigEndian, u)
	binary.Write(&b, binary.BigEndian, &payload)
	u.csum = checksum(b.Bytes())
}

// Conn represents connection
type Conn struct {
	fd      int
	IPSrc   net.IP
	IPDst   net.IP
	SrcPort uint16
	DstPort uint16
	sync.Mutex
}

func (c *Conn) Write(payload []byte) (int, error) {
	c.Lock()
	defer c.Unlock()
	return c.WriteAs(c.IPSrc, c.SrcPort, payload)
}

// WriteAs helps to write payload as an IP.
func (c *Conn) WriteAs(ipsrc net.IP, port uint16, payload []byte) (int, error) {
	addr := unix.SockaddrInet4{}

	ip := iphdr{
		vhl:   0x45,
		tos:   0,
		id:    0x1234, // the kernel overwrites id if it is zero
		off:   0,
		ttl:   64,
		proto: unix.IPPROTO_UDP,
	}
	copy(ip.src[:], ipsrc.To4())
	copy(ip.dst[:], c.IPDst.To4())
	// iplen and csum set later

	udp := udphdr{
		src: port,
		dst: c.DstPort,
	}
	if len(payload)+8+20 > 0xffff {
		log.Println("message is too large, truncating...")
		payload = payload[:0xffff-0x8-0x14]
	}
	udplen := 8 + len(payload)
	totalLen := 20 + udplen
	if totalLen > 0xffff {
		return 0, errors.New("message is too large to fit into a packet")
	}

	// the kernel will overwrite the IP checksum, so this is included just for
	// completeness
	ip.iplen = uint16(totalLen)
	ip.checksum()

	// the kernel doesn't touch the UDP checksum, so we can either set it
	// correctly or leave it zero to indicate that we didn't use a checksum
	udp.ulen = uint16(udplen)
	udp.checksum(&ip, payload)

	var b bytes.Buffer
	err := binary.Write(&b, binary.BigEndian, &ip)
	if err != nil {
		return 0, fmt.Errorf("error encoding the IP header: %v", err)
	}
	err = binary.Write(&b, binary.BigEndian, &udp)
	if err != nil {
		return 0, fmt.Errorf("error encoding the UDP header: %v", err)
	}
	err = binary.Write(&b, binary.BigEndian, &payload)
	if err != nil {
		return 0, fmt.Errorf("error encoding the payload: %v", err)
	}
	bb := b.Bytes()

	if runtime.GOOS == "darwin" {
		bb[2], bb[3] = bb[3], bb[2]
	}

	err = unix.Sendto(c.fd, bb, 0, &addr)
	if err != nil {
		return 0, err
	}

	return len(bb), nil
}

// Close closes descriptor.
func (c *Conn) Close() error {
	return unix.Close(c.fd)
}

// NewUDPConn returs connection.
func NewUDPConn(address string) (*Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	puint, err := strconv.ParseUint(port, 10, 32)
	if err != nil {
		return nil, err
	}

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil || fd < 0 {
		return nil, err
	}

	err = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1)
	if err != nil {
		return nil, err
	}

	return &Conn{
		fd:      fd,
		IPDst:   net.ParseIP(host),
		DstPort: uint16(puint),
		SrcPort: defaultSrcPort,
		IPSrc:   net.ParseIP(defaultSrcIP),
	}, nil
}
