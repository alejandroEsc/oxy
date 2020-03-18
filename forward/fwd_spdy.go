package forward

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"strings"

	"github.com/amahi/spdy"
	"github.com/joejulian/gspdy"
	log "github.com/sirupsen/logrus"
	"github.com/vulcand/oxy/utils"
	"k8s.io/apimachinery/pkg/util/httpstream"
	//sspdy "github.com/SlyMarbo/spdy"
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

	hijackedConn, rw, err := hijacker.Hijack()
	if err != nil {
		f.log.Errorf("%s error: unable to upgrade: unable to hijack and get connection %s", debugPrevix, err)
		return
	}

	conn := &rwConn{
		Conn:      hijackedConn,
		Reader:    io.MultiReader(rw),
		BufWriter: newSettingsAckSwallowWriter(rw.Writer),
	}

	defer conn.Close()

	session := spdy.NewServerSession(conn, &http.Server{})
	session.NewStreamProxy(req, w)
	defer session.Close()
}

// rwConn implements net.Conn but overrides Read and Write so that reads and
// writes are forwarded to the provided io.Reader and bufWriter.
type rwConn struct {
	net.Conn
	io.Reader
	BufWriter bufWriter
}

// Read forwards reads to the underlying Reader.
func (c *rwConn) Read(p []byte) (int, error) {
	return c.Reader.Read(p)
}

// Write forwards writes to the underlying bufWriter and immediately flushes.
func (c *rwConn) Write(p []byte) (int, error) {
	n, err := c.BufWriter.Write(p)
	if err := c.BufWriter.Flush(); err != nil {
		return 0, err
	}
	return n, err
}

// bufWriter is a Writer interface that also has a Flush method.
type bufWriter interface {
	io.Writer
	Flush() error
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

// settingsAckSwallowWriter is a writer that normally forwards bytes to it's
// underlying Writer, but swallows the first SettingsAck frame that it sees.
type settingsAckSwallowWriter struct {
	Writer     *bufio.Writer
	buf        []byte
	didSwallow bool
}

// newSettingsAckSwallowWriter returns a new settingsAckSwallowWriter.
func newSettingsAckSwallowWriter(w *bufio.Writer) *settingsAckSwallowWriter {
	return &settingsAckSwallowWriter{
		Writer:     w,
		buf:        make([]byte, 0),
		didSwallow: false,
	}
}

// Write implements io.Writer interface. Normally forwards bytes to w.Writer,
// except for the first Settings ACK frame that it sees.
func (w *settingsAckSwallowWriter) Write(p []byte) (int, error) {
	return w.Writer.Write(p)
}

// Flush calls w.Writer.Flush.
func (w *settingsAckSwallowWriter) Flush() error {
	return w.Writer.Flush()
}