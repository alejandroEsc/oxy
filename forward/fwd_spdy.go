package forward

import (
	"bufio"
	"context"
	"sync"

	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync/atomic"
	"time"

	"github.com/amahi/spdy"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/http/httpguts"
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
		defer f.log.Debugf("%s - done - ", debugPrefix)
	}

	// SO WE NEED TO DIAL. GET THE STREAMING SUPPORT FROM THE INDIVIDUAL WE ARE DIALING
	// INJECT THOSE HERE, MAYBE PART OF THE REQUEST?
	// THEN WE NEED TO HAVE THE TRANSFER OF DATA TO HAPPEN.

	//f.handleViaStreams(w, req, ctx)
	//f.handleViaConnection(w, req, ctx)
	f.handleViaReverseProxy(w, req, ctx)
}

func (f *httpForwarder) handleViaConnection(w http.ResponseWriter, req *http.Request, ctx *handlerContext) {
	f.log.Debugf("%s handleViaConnection", debugPrefix)

	// Upgrade Connection
	w.Header().Add(httpstream.HeaderConnection, httpstream.HeaderUpgrade)
	w.Header().Add(httpstream.HeaderUpgrade, k8spdy.HeaderSpdy31)

	// the protocal stream version
	f.log.Debugf("%s supported protocol versions: %v", debugPrefix, req.Header[httpstream.HeaderProtocolVersion])

	for _, p := range req.Header[httpstream.HeaderProtocolVersion] {
		w.Header().Add(httpstream.HeaderProtocolVersion, p)
	}

	w.WriteHeader(http.StatusSwitchingProtocols)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		f.log.Debugf("%s unable to upgrade: unable to hijack response", debugPrefix)
		return
	}

	conn, rw, err := hijacker.Hijack()
	if err != nil {
		f.log.Debugf("%s unable to upgrade: error hijacking response: %v", debugPrefix, err)
		return
	}

	c := connWrapper{
		Conn:      conn,
		bufReader: rw.Reader,
		bufWriter: rw.Writer,
	}
	//streamChan := make(chan httpstream.Stream, 1)
	//spdyConn, err := k8spdy.NewServerConnection(c, streamReceived(streamChan))
	//if err != nil {
	//	f.log.Debugf("%s unable to upgrade: error creating SPDY server connection: %v", debugPrefix, err)
	//	return
	//}
	//defer spdyConn.Close()
	//
	//<- spdyConn.CloseChan()

	// The Below is a dead-end seems like i need to reverse-proxy things
	session := spdy.NewServerSession(c, &http.Server{})
	session.Serve()
}

func (f *httpForwarder) handleViaReverseProxy(w http.ResponseWriter, req *http.Request, ctx *handlerContext) {
	f.log.Debugf("%s handleViaReverseProxy", debugPrefix)

	reqCtx := req.Context()
	if cn, ok := w.(http.CloseNotifier); ok {
		var cancel context.CancelFunc
		reqCtx, cancel = context.WithCancel(reqCtx)
		defer cancel()
		notifyChan := cn.CloseNotify()
		go func() {
			select {
			case <-notifyChan:
				cancel()
			case <-reqCtx.Done():
			}
		}()
	}

	outReq := req.Clone(reqCtx)
	if req.ContentLength == 0 {
		outReq.Body = nil // Issue 16036: nil Body for http.Transport retries
	}
	if outReq.Header == nil {
		outReq.Header = make(http.Header) // Issue 33142: historical behavior was to always allocate
	}

	//f.modifySPDYRequest(outReq, req.URL)
	f.modifyRequest(outReq, req.URL)
	outReq.Close = false

	f.log.Debugf("%s OutRequest: %v",debugPrefix, outReq)

	if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		// If we aren't the first proxy retain prior
		// X-Forwarded-For information as a comma+space
		// separated list and fold multiple headers into one.
		if prior, ok := outReq.Header["X-Forwarded-For"]; ok {
			clientIP = strings.Join(prior, ", ") + ", " + clientIP
		}
		outReq.Header.Set("X-Forwarded-For", clientIP)
	}

	// must clone and NextProtos to not use h2
	config := f.tlsClientConfig.Clone()
	config.NextProtos = []string{"h1"}

	spdyRountTripper := NewSpdyRoundTripper(config, true)

	res, err := spdyRountTripper.RoundTrip(outReq)
	if err != nil {
		f.log.Debugf("%s error retrieving response: %s", debugPrefix, err)
		return
	}

	f.log.Debugf("%s Res: %v",debugPrefix, res)

	// Deal with 101 Switching Protocols responses: (WebSocket, h2c, etc)
	if res.StatusCode == http.StatusSwitchingProtocols {
		f.log.Debugf("%s The response has a 101 switch protocol response, we are handling it now", debugPrefix)
		f.handleViaStreams(w, outReq, ctx)
		resConn := spdyRountTripper.RespondConn()
		if err != nil {
			f.log.Debugf("%s error creating a response connection %s", debugPrefix, err)
			return
		}
		handleUpgradeResponse(w, outReq, res, resConn)
		return
	}

	removeConnectionHeaders(res.Header)

	for _, h := range hopHeaders {
		res.Header.Del(h)
	}

	copyHeader(w.Header(), res.Header)

	// The "Trailer" header isn't included in the Transport's response,
	// at least for *http.Transport. Build it up from Trailer.
	announcedTrailers := len(res.Trailer)
	if announcedTrailers > 0 {
		trailerKeys := make([]string, 0, len(res.Trailer))
		for k := range res.Trailer {
			trailerKeys = append(trailerKeys, k)
		}
		w.Header().Add("Trailer", strings.Join(trailerKeys, ", "))
	}

	w.WriteHeader(res.StatusCode)

	err = copyResponse(w, res.Body, flushInterval(req, res, f.flushInterval), f.bufferPool)
	if err != nil {
		defer res.Body.Close()
		// Since we're streaming the response, if we run into an error all we can do
		// is abort the request. Issue 23643: ReverseProxy should use ErrAbortHandler
		// on read error while copying body.
		if !shouldPanicOnCopyError(req) {
			f.log.Debugf("suppressing panic for copyResponse error in test; copy error: %v", err)
			return
		}
		panic(http.ErrAbortHandler)
	}
	res.Body.Close() // close now, instead of defer, to populate res.Trailer

	if len(res.Trailer) > 0 {
		// Force chunking if we saw a response trailer.
		// This prevents net/http from calculating the length for short
		// bodies and adding a Content-Length.
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
	}

	if len(res.Trailer) == announcedTrailers {
		copyHeader(w.Header(), res.Trailer)
		return
	}

	for k, vv := range res.Trailer {
		k = http.TrailerPrefix + k
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}

}

func (f *httpForwarder) handleViaStreams(w http.ResponseWriter, req *http.Request, ctx *handlerContext) {
	streamChan := make(chan httpstream.Stream, 1)

	upgrader := k8spdy.NewResponseUpgrader()

	spdyConn := upgrader.UpgradeResponse(w, req, streamReceived(streamChan))
	if spdyConn == nil {
		return
	}
	defer spdyConn.Close()

	h := &StreamHandler{
		conn:                  spdyConn,
		streamChan:            streamChan,
		streamPairs:           make(map[string]*StreamPair),
		streamCreationTimeout: 1*time.Minute,
	}
	h.run()

	// blocks until connection is done
	//<- spdyConn.CloseChan()
}

func streamReceived(streams chan httpstream.Stream) func(httpstream.Stream, <-chan struct{}) error {
	return func(stream httpstream.Stream, replySent <-chan struct{}) error {
		streams <- stream
		return nil
	}
}

// IsSPDYRequest determines if the specified HTTP request is a
// SPDY/3.1 handshake request
func IsSPDYRequest(req *http.Request) bool {
	log.Debugf("AE: Request PROTOCOL is: %s , source %s, path %s",req.Proto, req.Host, req.URL.Path)
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

// connWrapper is used to wrap a hijacked connection and its bufio.Reader. All
// calls will be handled directly by the underlying net.Conn with the exception
// of Read and Close calls, which will consider data in the bufio.Reader. This
// ensures that data already inside the used bufio.Reader instance is also
// read.
type connWrapper struct {
	net.Conn
	closed    int32
	bufReader *bufio.Reader
	bufWriter *bufio.Writer
}

func (c connWrapper) Read(b []byte) (int, error) {
	if atomic.LoadInt32(&c.closed) == 1 {
		return 0, io.EOF
	}
	return c.bufReader.Read(b)
}

func (c connWrapper) Write(b []byte) (int, error) {
	n, err := c.bufWriter.Write(b)
	if err := c.bufWriter.Flush(); err != nil {
		return 0, err
	}
	return n, err
}

func (c connWrapper) Close() error {
	err := c.Conn.Close()
	atomic.StoreInt32(&c.closed, 1)
	return err
}


var hopHeaders = []string{
	"Connection",
	"Proxy-Connection", // non-standard but still sent by libcurl and rejected by e.g. google
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",      // canonicalized version of "TE"
	"Trailer", // not Trailers per URL above; https://www.rfc-editor.org/errata_search.php?eid=4522
	"Transfer-Encoding",
	"Upgrade",
}

// removeConnectionHeaders removes hop-by-hop headers listed in the "Connection" header of h.
// See RFC 7230, section 6.1
func removeConnectionHeaders(h http.Header) {
	for _, f := range h["Connection"] {
		for _, sf := range strings.Split(f, ",") {
			if sf = strings.TrimSpace(sf); sf != "" {
				h.Del(sf)
			}
		}
	}
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func copyResponse(dst io.Writer, src io.Reader, flushInterval time.Duration, bufferPool httputil.BufferPool ) error {
	if flushInterval != 0 {
		if wf, ok := dst.(writeFlusher); ok {
			mlw := &maxLatencyWriter{
				dst:     wf,
				latency: flushInterval,
			}
			defer mlw.stop()

			// set up initial timer so headers get flushed even if body writes are delayed
			mlw.flushPending = true
			mlw.t = time.AfterFunc(flushInterval, mlw.delayedFlush)

			dst = mlw
		}
	}

	var buf []byte
	if bufferPool != nil {
		buf = bufferPool.Get()
		defer bufferPool.Put(buf)
	}
	_, err := copyBuffer(dst, src, buf)
	return err
}

func copyBuffer(dst io.Writer, src io.Reader, buf []byte) (int64, error) {
	if len(buf) == 0 {
		buf = make([]byte, 32*1024)
	}
	var written int64
	for {
		nr, rerr := src.Read(buf)
		if rerr != nil && rerr != io.EOF && rerr != context.Canceled {
			log.Debugf("httputil: ReverseProxy read error during body copy: %v", rerr)
		}
		if nr > 0 {
			nw, werr := dst.Write(buf[:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if werr != nil {
				return written, werr
			}
			if nr != nw {
				return written, io.ErrShortWrite
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				rerr = nil
			}
			return written, rerr
		}
	}
}

type writeFlusher interface {
	io.Writer
	http.Flusher
}

type maxLatencyWriter struct {
	dst     writeFlusher
	latency time.Duration // non-zero; negative means to flush immediately

	mu           sync.Mutex // protects t, flushPending, and dst.Flush
	t            *time.Timer
	flushPending bool
}

func (m *maxLatencyWriter) Write(p []byte) (n int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, err = m.dst.Write(p)
	if m.latency < 0 {
		m.dst.Flush()
		return
	}
	if m.flushPending {
		return
	}
	if m.t == nil {
		m.t = time.AfterFunc(m.latency, m.delayedFlush)
	} else {
		m.t.Reset(m.latency)
	}
	m.flushPending = true
	return
}

func (m *maxLatencyWriter) delayedFlush() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.flushPending { // if stop was called but AfterFunc already started this goroutine
		return
	}
	m.dst.Flush()
	m.flushPending = false
}

func (m *maxLatencyWriter) stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.flushPending = false
	if m.t != nil {
		m.t.Stop()
	}
}

// flushInterval returns the p.FlushInterval value, conditionally
// overriding its value for a specific request/response.
func flushInterval(req *http.Request, res *http.Response, flushInterval time.Duration) time.Duration {
	resCT := res.Header.Get("Content-Type")

	// For Server-Sent Events responses, flush immediately.
	// The MIME type is defined in https://www.w3.org/TR/eventsource/#text-event-stream
	if resCT == "text/event-stream" {
		return -1 // negative means immediately
	}

	// TODO: more specific cases? e.g. res.ContentLength == -1?
	return flushInterval
}

func shouldPanicOnCopyError(req *http.Request) bool {
	if req.Context().Value(http.ServerContextKey) != nil {
		// We seem to be running under an HTTP server, so
		// it'll recover the panic.
		return true
	}
	// Otherwise act like Go 1.10 and earlier to not break
	// existing tests.
	return false
}

func upgradeType(h http.Header) string {
	if !httpguts.HeaderValuesContainsToken(h["Connection"], "Upgrade") {
		return ""
	}
	return strings.ToLower(h.Get("Upgrade"))
}

func handleUpgradeResponse(rw http.ResponseWriter, req *http.Request, res *http.Response, backConn net.Conn) {
	log.Debugf("%s handleUpgradeResponse", debugPrefix)
	reqUpType := upgradeType(req.Header)
	resUpType := upgradeType(res.Header)
	if reqUpType != resUpType {
		log.Debugf("backend tried to switch protocol %q when %q was requested", resUpType, reqUpType)
		return
	}

	copyHeader(res.Header, rw.Header())

	hj, ok := rw.(http.Hijacker)
	if !ok {
		log.Debugf("can't switch protocols using non-Hijacker ResponseWriter type %T", rw)
		return
	}
	defer backConn.Close()
	conn, brw, err := hj.Hijack()
	if err != nil {
		log.Debugf("Hijack failed on protocol switch: %v", err)
		return
	}
	defer conn.Close()
	res.Body = nil // so res.Write only writes the headers; we have res.Body in backConn above
	if err := res.Write(brw); err != nil {
		log.Debugf("response write: %v", err)
		return
	}
	if err := brw.Flush(); err != nil {
		log.Debugf("response flush: %v", err)
		return
	}
	errc := make(chan error, 1)
	spc := switchProtocolCopier{user: conn, backend: backConn}
	go spc.copyToBackend(errc)
	go spc.copyFromBackend(errc)
	<-errc
	return
}

// switchProtocolCopier exists so goroutines proxying data back and
// forth have nice names in stacks.
type switchProtocolCopier struct {
	user, backend io.ReadWriter
}

func (c switchProtocolCopier) copyFromBackend(errc chan<- error) {
	_, err := io.Copy(c.user, c.backend)
	errc <- err
}

func (c switchProtocolCopier) copyToBackend(errc chan<- error) {
	_, err := io.Copy(c.backend, c.user)
	errc <- err
}


