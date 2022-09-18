package HttpHandler

import (
	"MyHoneyProxy/HoneyProxy"
	"bytes"
	"io"
	"net/http"
)

func copyResponse(resp *http.Response)[]byte {
	data, _ := io.ReadAll(resp.Body)
	if len(data) == 0{
		return nil
	}
	resp.Body = io.NopCloser(bytes.NewReader(data))
	return data
}

func HandleResponse(resp *http.Response, ctx *HoneyProxy.ProxyCtx) *http.Response {
	if ctx.UserData == nil {
		return resp
	}
	httpMiddle := ctx.UserData.(*HttpMiddle)
	httpMiddle.ResponseBody = copyResponse(resp)
	if len(httpMiddle.RequestBody) != 0{
		//log.Println("请求:",string(httpMiddle.RequestBody))
	}
	//log.Println("响应:",string(httpMiddle.ResponseBody))
	return resp
}