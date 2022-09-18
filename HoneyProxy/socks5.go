package HoneyProxy

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strconv"
)

// AddrSpec is used to return the target AddrSpec
// which may be specified as IPv4, IPv6, or a FQDN
type AddrSpec struct {
	FQDN string
	IP   net.IP
	Port int
}

type Socks5Request struct {
	Version uint8
	Command uint8
	DestAddr *AddrSpec
}

func (this *AddrSpec)realAddr()string  {
	if this.FQDN != ""{
		return net.JoinHostPort(this.FQDN,strconv.Itoa(this.Port))
	}
	return net.JoinHostPort(this.IP.String(),strconv.Itoa(this.Port))
}

func readAddrSpec(r io.Reader) (*AddrSpec, error) {
	d := &AddrSpec{}

	// Get the address type
	addrType := []byte{0}
	if _, err := r.Read(addrType); err != nil {
		return nil, err
	}

	// Handle on a per type basis
	switch addrType[0] {
	case 0x1:	//ipv4Address
		addr := make([]byte, 4)
		if _, err := io.ReadAtLeast(r, addr, len(addr)); err != nil {
			return nil, err
		}
		d.IP = net.IP(addr)
	case 0x4:	//ipv6Address
		addr := make([]byte, 16)
		if _, err := io.ReadAtLeast(r, addr, len(addr)); err != nil {
			return nil, err
		}
		d.IP = net.IP(addr)
	case 0x3:	//fqdnAddress
		if _, err := r.Read(addrType); err != nil {
			return nil, err
		}
		addrLen := int(addrType[0])
		fqdn := make([]byte, addrLen)
		if _, err := io.ReadAtLeast(r, fqdn, addrLen); err != nil {
			return nil, err
		}
		d.FQDN = string(fqdn)

	default:
		return nil, errors.New("Unrecognized address type")
	}

	// Read the port
	port := []byte{0, 0}
	if _, err := io.ReadAtLeast(r, port, 2); err != nil {
		return nil, err
	}
	d.Port = (int(port[0]) << 8) | int(port[1])

	return d, nil
}

// sendReply is used to send a reply message
func sendReply(w io.Writer, resp uint8, addr *AddrSpec) error {
	// Format the address
	var addrType uint8
	var addrBody []byte
	var addrPort uint16
	switch {
	case addr == nil:
		addrType = 0x1	//ipv4Address
		addrBody = []byte{0, 0, 0, 0}
		addrPort = 0

	case addr.FQDN != "":
		addrType = 0x3	//fqdnAddress
		addrBody = append([]byte{byte(len(addr.FQDN))}, addr.FQDN...)
		addrPort = uint16(addr.Port)

	case addr.IP.To4() != nil:
		addrType = 0x1	//ipv4Address
		addrBody = []byte(addr.IP.To4())
		addrPort = uint16(addr.Port)

	case addr.IP.To16() != nil:
		addrType = 0x4	//ipv6Address
		addrBody = []byte(addr.IP.To16())
		addrPort = uint16(addr.Port)

	default:
		return errors.New("Failed to format address")
	}

	// Format the message
	msg := make([]byte, 6+len(addrBody))
	msg[0] = 0x5
	msg[1] = resp
	msg[2] = 0 // Reserved
	msg[3] = addrType
	copy(msg[4:], addrBody)
	msg[4+len(addrBody)] = byte(addrPort >> 8)
	msg[4+len(addrBody)+1] = byte(addrPort & 0xff)

	// Send the message
	_, err := w.Write(msg)
	return err
}

func readMethods(r io.Reader) ([]byte, error) {
	header := []byte{0}
	if _, err := r.Read(header); err != nil {
		return nil, err
	}
	numMethods := int(header[0])
	methods := make([]byte, numMethods)
	_, err := io.ReadAtLeast(r, methods, numMethods)
	return methods, err
}

func (this *HoneyProxy)socks5_ReadUsernamePassword(conn *bufferedConn)(string, string, error) {
	header := []byte{0, 0}
	_, err := io.ReadAtLeast(conn, header, 2)
	if err != nil {
		return "", "", err
	}
	userName := make([]byte,header[1])
	_,err = io.ReadAtLeast(conn.r,userName,int(header[1]))
	if err != nil{
		return "","",err
	}
	var nPwdLen uint8
	nPwdLen, err = conn.ReadByte()
	if err != nil{
		return "","",err
	}
	passWord := make([]byte,nPwdLen)
	_,err = io.ReadAtLeast(conn.r,passWord,int(nPwdLen))
	if err != nil{
		return "","",err
	}
	return string(userName),string(passWord),nil
}

func (this *HoneyProxy)socks5_auth(bufConn *bufferedConn,ctx *ProxyCtx)error  {

	bufConn.ReadByte()
	methods, err := readMethods(bufConn)
	if err != nil {
		return err
	}
	//需要用户名密码
	if bytes.Contains(methods,[]byte{0x2}) == true{
		_,err = bufConn.Write([]byte{0x5,0x2})
		if err != nil{
			return err
		}
		ctx.ProxyAuth.UserName,ctx.ProxyAuth.PassWord, err = this.socks5_ReadUsernamePassword(bufConn)
		if err != nil{
			return err
		}
		//授权通过
		_,err = bufConn.Write([]byte{0x1,0x00})
		return err
	}
	_,err = bufConn.Write([]byte{0x5,0x0})
	if err != nil{
		return err
	}
	return err
}

func (this *HoneyProxy)NewSocks5Request(bufConn io.Reader)(retHeader *Socks5Request,retErr error)  {

	header := []byte{0, 0, 0}
	if _, err := io.ReadAtLeast(bufConn, header, 3); err != nil {
		return nil,errors.New("Failed to get command version")
	}

	if header[0] != 0x5 {
		return nil, errors.New("Unsupported command version")
	}

	// Read in the destination address
	dest, err := readAddrSpec(bufConn)
	if err != nil {
		return nil, err
	}
	request := &Socks5Request{
		Version:  0x5,
		Command:  header[1],
		DestAddr: dest,
	}
	return request, nil
}

func (this *HoneyProxy)handleSocks5Cmd_Connect(bufConn *bufferedConn,socksReq *Socks5Request,ctx *ProxyCtx)error  {

	local := bufConn.LocalAddr().(*net.TCPAddr)
	err := sendReply(bufConn,0x0,&AddrSpec{IP: local.IP, Port: local.Port})
	if err != nil{
		return err
	}

	peekHeader,err := bufConn.Peek(3)
	if err != nil{
		return err
	}

	//TLS ClientHello magic
	if peekHeader[0] == 0x16 && peekHeader[1] == 0x3 && peekHeader[2] <= 0x3{
		tlsConfig, err := TLSConfigFromCA(socksReq.DestAddr.realAddr(),ctx)
		if err != nil{
			return err
		}
		rawClientTls := tls.Server(bufConn,tlsConfig)
		defer rawClientTls.Close()
		err = rawClientTls.Handshake()
		if err != nil {
			return err
		}
		return this.executeHttpsRequest(rawClientTls,ctx)
	}

	//检查http请求
	switch peekHeader[0] {
	case 'O':	//options
		fallthrough
	case 'P':	//post,put,patch
		fallthrough
	case 'T':	//trace
		fallthrough
	case 'D':	//delete
		fallthrough
	case 'H':	//head
		fallthrough
	case 'G':	//get
		return this.handleHttpRequest(bufConn,ctx)
	}
	return nil
}

func (this *HoneyProxy)handleSocks5Request(bufConn *bufferedConn,ctx *ProxyCtx)error  {

	err := this.socks5_auth(bufConn,ctx)
	if err != nil{
		return err
	}
	socksHeader,err := this.NewSocks5Request(bufConn)
	if err != nil{
		return err
	}
	switch socksHeader.Command {
	case 0x1:	//connect
		return this.handleSocks5Cmd_Connect(bufConn,socksHeader,ctx)
	case 0x2:	//bind
	case 0x3:	//associate
		
	}
	return nil
}