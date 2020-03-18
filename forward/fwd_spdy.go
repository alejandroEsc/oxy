package forward

import (
	"fmt"
	//"bytes"
	//"fmt"
	//"io"
	"net/http"
	"reflect"
	"strings"

	"github.com/joejulian/gspdy"
	log "github.com/sirupsen/logrus"
	"github.com/vulcand/oxy/utils"
	//"github.com/amahi/spdy"
	sspdy "github.com/SlyMarbo/spdy"
	k8spdy "k8s.io/apimachinery/pkg/util/httpstream/spdy"
	"k8s.io/apimachinery/pkg/util/httpstream"
)

const (
	debugPrevix = "AE: vulcand/oxy/forward/spdy: "
)

// serveHTTP forwards spdy traffic
func (f *httpForwarder) serveSPDY(w http.ResponseWriter, req *http.Request, ctx *handlerContext) {

	if f.log.GetLevel() >= log.DebugLevel {
		logEntry := f.log.WithField("Request", utils.DumpHttpRequest(req))
		logEntry.Debug("vulcand/oxy/forward/spdy: begin ServeHttp on request")
		defer logEntry.Debug("vulcand/oxy/forward/spdy: completed ServeHttp on request")
	}

	outReq := f.copySPDYRequest(req)

	dialer := gspdy.DefaultDialer

	if outReq.URL.Scheme == "https" && f.tlsClientConfig != nil {
		dialer.TLSClientConfig = f.tlsClientConfig.Clone()
		// WebSocket is only in http/1.1
		dialer.TLSClientConfig.NextProtos = []string{"http/1.1"}
	}

	// DIAL and set up error servers for error handling
	_, resp, err := dialer.DialContext(outReq.Context(), outReq.URL.String(), outReq.Header)
	//targetConn, resp, err := dialer.DialContext(outReq.Context(), outReq.URL.String(), outReq.Header)
	if err != nil {
		if resp == nil {
			ctx.errHandler.ServeHTTP(w, req, err)
		} else {
			f.log.Errorf("vulcand/oxy/forward/websocket: Error dialing %q: %v with resp: %d %s", outReq.Host, err, resp.StatusCode, resp.Status)
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				f.log.Errorf("vulcand/oxy/forward/websocket: %s can not be hijack", reflect.TypeOf(w))
				ctx.errHandler.ServeHTTP(w, req, err)
				return
			}

			conn, _, errHijack := hijacker.Hijack()
			if errHijack != nil {
				f.log.Errorf("vulcand/oxy/forward/websocket: Failed to hijack responseWriter")
				ctx.errHandler.ServeHTTP(w, req, errHijack)
				return
			}
			defer func() {
				conn.Close()
				if f.websocketConnectionClosedHook != nil {
					f.websocketConnectionClosedHook(req, conn)
				}
			}()

			errWrite := resp.Write(conn)
			if errWrite != nil {
				f.log.Errorf("vulcand/oxy/forward/websocket: Failed to forward response")
				ctx.errHandler.ServeHTTP(w, req, errWrite)
				return
			}
		}
		f.log.Errorf("%s error: with response %s", debugPrevix, err)
		return
	}

	// upgrade the connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		errorMsg := fmt.Sprintf("unable to upgrade: unable to hijack response")
		http.Error(w, errorMsg, http.StatusInternalServerError)
		f.log.Errorf("%s error: unable to upgrade: unable to hijack response %s", debugPrevix, err)
		return
	}

	w.Header().Add(httpstream.HeaderConnection, httpstream.HeaderUpgrade)
	w.Header().Add(httpstream.HeaderUpgrade, k8spdy.HeaderSpdy31)
	w.WriteHeader(http.StatusSwitchingProtocols)

	conn, _, err := hijacker.Hijack()
	if err != nil {
		f.log.Errorf("%s error: unable to upgrade: unable to hijack and get connection %s", debugPrevix, err)
		return
	}

	defer conn.Close()

	// Send the connection accepted response.
	res := new(http.Response)
	res.Status = "200 Connection Established"
	res.StatusCode = http.StatusOK
	res.Proto = "HTTP/1.1"
	res.ProtoMajor = 1
	res.ProtoMinor = 1
	if err = res.Write(conn); err != nil {
		f.log.Errorf("Failed to send connection established message in ProxyConnections.", err)
		return
	}

	client, err := sspdy.NewClientConn(conn, nil, 3, 1)

	if err != nil {
		f.log.Errorf("Error creating SPDY connection in ProxyConnections.", err)
		return
	}

	go client.Run()

	client.Close()
}

// copySPDYRequest makes a copy of the specified request.
func (f *httpForwarder) copySPDYRequest(req *http.Request) (outReq *http.Request) {
	outReq = new(http.Request)
	*outReq = *req // includes shallow copies of maps, but we handle this below

	outReq.URL = utils.CopyURL(req.URL)
	outReq.URL.Scheme = req.URL.Scheme

	u := f.getUrlFromRequest(outReq)

	outReq.URL.Path = u.Path
	outReq.URL.RawPath = u.RawPath
	outReq.URL.RawQuery = u.RawQuery
	outReq.RequestURI = "" // Outgoing request should not have RequestURI

	outReq.URL.Host = req.URL.Host
	if !f.passHost {
		outReq.Host = req.URL.Host
	}

	outReq.Header = make(http.Header)

	// gorilla websocket use this header to set the request.Host tested in checkSameOrigin
	outReq.Header.Set("Host", outReq.Host)
	utils.CopyHeaders(outReq.Header, req.Header)
	utils.RemoveHeaders(outReq.Header, WebsocketDialHeaders...)

	if f.rewriter != nil {
		f.rewriter.Rewrite(outReq)
	}
	return outReq
}

// IsSPDYRequest determines if the specified HTTP request is a
// SPDY/3.1 handshake request
func IsSPDYRequest(req *http.Request) bool {
	containsHeader := func(name, value string) bool {
		items := strings.Split(req.Header.Get(name), ",")
		for _, item := range items {
			if value == strings.ToLower(strings.TrimSpace(item)) {
				return true
			}
		}
		return false
	}
	return containsHeader(Connection, "upgrade") && containsHeader(Upgrade, "spdy/3.1")
}