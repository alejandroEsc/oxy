package forward

import (
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
	k8spdy "k8s.io/apimachinery/pkg/util/httpstream/spdy"
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

	upgrader := k8spdy.NewResponseUpgrader()
	// Only the targetConn choose to CheckOrigin or not
	//upgrader := gspdy.Upgrader{CheckOrigin: func(r *http.Request) bool {
	//	return true
	//}}

	//utils.RemoveHeaders(resp.Header, WebsocketUpgradeHeaders...)
	//utils.CopyHeaders(resp.Header, w.Header())

	streamConnection := upgrader.UpgradeResponse(w, req, nil)
	defer streamConnection.Close()

	//session := spdy.NewServerSession(streamConnection., &http.Server{})
	//session.Serve()


	//underlyingConn, err := upgrader.Upgrade(w, req, resp.Header)
	//if err != nil {
	//	f.log.Errorf("%s error: while upgrading connection : %v", debugPrevix, err)
	//	return
	//}
	//defer func() {
	//	f.log.Debugf("%s closing underlying connection", debugPrevix)
	//	underlyingConn.Close()
	//	targetConn.Close()
	//	if f.websocketConnectionClosedHook != nil {
	//		f.websocketConnectionClosedHook(req, underlyingConn.UnderlyingConn())
	//	}
	//}()

	//errClient := make(chan error, 1)
	//errBackend := make(chan error, 1)


	//replicateSPDYConn := func(dst, src *gspdy.Conn, errc chan error) {
	//
	//	forward := func(messageType int, reader io.Reader) error {
	//		writer, err := dst.NextWriter(messageType)
	//		if err != nil {
	//			return err
	//		}
	//		_, err = io.Copy(writer, reader)
	//		if err != nil {
	//			return err
	//		}
	//		return writer.Close()
	//	}
	//
	//	src.SetPingHandler(func(data string) error {
	//		return forward(gspdy.PingMessage, bytes.NewReader([]byte(data)))
	//	})
	//
	//	src.SetPongHandler(func(data string) error {
	//		return forward(gspdy.PongMessage, bytes.NewReader([]byte(data)))
	//	})
	//
	//	for {
	//		msgType, reader, err := src.NextReader()
	//
	//		if err != nil {
	//			m := gspdy.FormatCloseMessage(gspdy.CloseNormalClosure, fmt.Sprintf("%v", err))
	//			if e, ok := err.(*gspdy.CloseError); ok {
	//				if e.Code != gspdy.CloseNoStatusReceived {
	//					m = nil
	//					// Following codes are not valid on the wire so just close the
	//					// underlying TCP connection without sending a close frame.
	//					if e.Code != gspdy.CloseAbnormalClosure &&
	//						e.Code != gspdy.CloseTLSHandshake {
	//
	//						m = gspdy.FormatCloseMessage(e.Code, e.Text)
	//					}
	//				}
	//			}
	//			errc <- err
	//			if m != nil {
	//				forward(gspdy.CloseMessage, bytes.NewReader([]byte(m)))
	//			}
	//			break
	//		}
	//		err = forward(msgType, reader)
	//		if err != nil {
	//			errc <- err
	//			break
	//		}
	//	}
	//}
	//
	//go replicateSPDYConn(underlyingConn, targetConn, errClient)
	//go replicateSPDYConn(targetConn, underlyingConn, errBackend)
	//
	//var message string
	//select {
	//case err = <-errClient:
	//	message = "vulcand/oxy/forward/spdy: Error when copying from backend to client: %v"
	//case err = <-errBackend:
	//	message = "vulcand/oxy/forward/spdy: Error when copying from client to backend: %v"
	//
	//}
	//if e, ok := err.(*gspdy.CloseError); !ok || e.Code == gspdy.CloseAbnormalClosure {
	//	f.log.Errorf(message, err)
	//}
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