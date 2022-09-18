package HoneyProxy

import (
	"crypto/tls"
	"net"
	"net/http"
	"strconv"
)

type protocol uint8
const(
	protocol_unknown protocol = 0x0
	protocol_socks4 protocol = 0x1
	protocol_socks5 protocol = 0x2
	protocol_http protocol = 0x3
	protocol_https protocol = 0x4
)

var(
	uClient = http.Client{
		Transport:&http.Transport{
			TLSClientConfig:&tls.Config{InsecureSkipVerify:true}},
	}
)

type HoneyProxy struct {
	//参数req为请求,返回req为新请求,返回resp不为空表示填充响应
	reqHandler	func(req *http.Request, ctx *ProxyCtx) (*http.Request, *http.Response)
	//参数resp为响应,返回resp为新响应
	respHandler func(resp *http.Response, ctx *ProxyCtx)*http.Response
	Tr *http.Transport
}

func NewHoneyProxy()*HoneyProxy{
	return &HoneyProxy{
		Tr:&http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, Proxy: http.ProxyFromEnvironment},
	}
}

func (this *HoneyProxy)filterRequest(req *http.Request, ctx *ProxyCtx)(*http.Request, *http.Response) {
	if this.reqHandler != nil{
		return this.reqHandler(req,ctx)
	}
	return req,nil
}

func (this *HoneyProxy)filterResponse(respOrig *http.Response, ctx *ProxyCtx)*http.Response  {
	if this.respHandler != nil{
		return this.respHandler(respOrig,ctx)
	}
	return respOrig
}

func (this *HoneyProxy)SetReqHandler(reqHandler func(req *http.Request, ctx *ProxyCtx) (*http.Request, *http.Response))  {
	this.reqHandler = reqHandler
}

func (this *HoneyProxy)SetRespHandler(respHandler func(resp *http.Response, ctx *ProxyCtx)*http.Response)  {
	this.respHandler = respHandler
}

//接收完整的数据,以\r\n\r\n作为结尾

func (this *HoneyProxy)readCompleteReq(conn net.Conn)(retBuf []byte,retErr error)  {
	//这里需要解决内存池和数据预读取的问题
	//默认缓冲区大小
	const tmpBufferSize = 0x2000
	for true{
		tmpBuffer := make([]byte,tmpBufferSize)
		nLen, err := conn.Read(tmpBuffer)
		if err != nil{
			return retBuf,err
		}
		retBuf = append(retBuf, tmpBuffer[0:nLen]...)
		//已经读取完毕
		if nLen < tmpBufferSize{
			return retBuf,nil
		}
	}
	return retBuf,nil
}


func (this *HoneyProxy)handleConn(conn net.Conn)error  {

	defer conn.Close()

	bufConn := newBufferedConn(conn)
	reqHeader,err := bufConn.Peek(1)
	if err != nil{
		return err
	}

	ctx := &ProxyCtx{Proxy: this,RemoteAddr: conn.RemoteAddr()}
	switch reqHeader[0] {
	case 0x4:
		ctx.Protocol = protocol_socks4
		return this.handleSocks4Request(&bufConn,ctx)
	case 0x5:
		ctx.Protocol = protocol_socks5
		return this.handleSocks5Request(&bufConn,ctx)
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
		ctx.Protocol = protocol_http
		return this.handleHttpRequest(&bufConn,ctx)
	case 'C':	//connect
		ctx.Protocol = protocol_https
		tlsConfig,err := this.https_prepareRequest(&bufConn,ctx)
		if err != nil {
			return err
		}
		return this.handleHttpsRequest(&bufConn,tlsConfig,ctx)
	}
	return nil
}

func (this *HoneyProxy)StartProxy(port int)error  {
	ls,err := net.Listen("tcp",":" + strconv.Itoa(port))
	if err != nil{
		return err
	}
	defer ls.Close()
	for true{
		conn,err := ls.Accept()
		if err != nil{
			continue
		}
 		go this.handleConn(conn)
	}
	return nil
}
