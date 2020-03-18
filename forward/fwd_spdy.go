package forward

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/amahi/spdy"
	log "github.com/sirupsen/logrus"
	"github.com/vulcand/oxy/utils"
	"k8s.io/apimachinery/pkg/util/httpstream"
	//sspdy "github.com/SlyMarbo/spdy"
	k8spdy "k8s.io/apimachinery/pkg/util/httpstream/spdy"
)

const (
	debugPrefix = "AE: vulcand/oxy/forward/spdy: "
)

// serveHTTP forwards spdy traffic
func (f *httpForwarder) serveSPDY(w http.ResponseWriter, req *http.Request, ctx *handlerContext) {

	if f.log.GetLevel() >= log.DebugLevel {
		logEntry := f.log.WithField("Request", utils.DumpHttpRequest(req))
		logEntry.Debugf("%s vulcand/oxy/forward/spdy: begin ServeHttp on request", debugPrefix)
		defer logEntry.Debugf("%s vulcand/oxy/forward/spdy: done", debugPrefix)
	}

	// upgrade the connection
	f.log.Debugf("%s hijacking connection", debugPrefix)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "unable to upgrade: unable to hijack response", http.StatusInternalServerError)
		f.log.Errorf("%s error: unable to upgrade: unable to hijack response", debugPrefix)
		return
	}

	f.log.Debugf("%s writting upgrade headers", debugPrefix)

	w.Header().Add(httpstream.HeaderConnection, httpstream.HeaderUpgrade)
	w.Header().Add(httpstream.HeaderUpgrade, k8spdy.HeaderSpdy31)
	w.WriteHeader(http.StatusSwitchingProtocols)

	f.log.Debugf("%s do the hijacking", debugPrefix)
	hijackedConn, _, err := hijacker.Hijack()
	if err != nil {
		f.log.Errorf("%s error: unable to upgrade: unable to hijack and get connection %s", debugPrefix, err)
		return
	}

	//f.log.Debugf("%s create the connection, this may be wrong", debugPrefix)
	//conn := &rwConn{
	//	Conn:      hijackedConn,
	//	Reader:    io.MultiReader(rw),
	//	BufWriter: newSettingsAckSwallowWriter(rw.Writer),
	//}

	defer hijackedConn.Close()

	// HERE we may want instead to have a reverse proxy, which we should look into doing that rather then serving this

	f.log.Debugf("%s create new session", debugPrefix)
	session := spdy.NewServerSession(hijackedConn, &http.Server{})
	f.log.Debugf("%s serve", debugPrefix)

	session.Serve()
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