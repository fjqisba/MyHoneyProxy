package HoneyProxy

import (
	"crypto/tls"
	"io"
	"net"
)

type SocksRequest4 struct {
	Hostname string
	IP net.IP
	Port int
	Username string
}

func (this *HoneyProxy)handleSocks4Request(bufConn *bufferedConn,ctx *ProxyCtx)error  {

	var socks4ReqHeader [8]byte
	_, err := io.ReadFull(bufConn, socks4ReqHeader[:])
	if err != nil {
		return err
	}

	//客户端访问端口
	//targetPort := int(binary.BigEndian.Uint16(socks4ReqHeader[2:4]))
	ip := socks4ReqHeader[4:8]
	socks4a := ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0
	ctx.ProxyAuth.UserName, err = readUntilNull(bufConn)
	if err != nil{
		return err
	}
	//var realAddr string
	var hostName string
	//var IP net.IP
	if socks4a {
		hostName, err = readUntilNull(bufConn)
		if err != nil{
			return err
		}
		//realAddr = net.JoinHostPort(hostName, strconv.Itoa(targetPort))
	}else{
		//IP = net.IPv4(ip[0], ip[1], ip[2], ip[3])
		//realAddr = net.JoinHostPort(IP.String(), strconv.Itoa(targetPort))
	}

	//sock4连接成功
	var responseData [8]byte
	responseData[1] = byte(0x5a)
	copy(responseData[2:8], socks4ReqHeader[2:])
	_, err = bufConn.Write(responseData[:])
	if err != nil {
		return err
	}

	peekHeader,err := bufConn.Peek(3)
	if err != nil{
		return err
	}

	//TLS ClientHello magic
	if peekHeader[0] == 0x16 && peekHeader[1] == 0x3 && peekHeader[2] <= 0x3{
		tlsConfig, err := TLSConfigFromCA(hostName,ctx)
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