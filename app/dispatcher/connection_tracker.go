package dispatcher

import (
	"context"
	"encoding/json"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
)

type trackedConnectionMetadata struct {
	UID               int    `json:"uid"`
	Network           string `json:"network"`
	Type              string `json:"type"`
	SourceIP          string `json:"sourceIP"`
	SourcePort        string `json:"sourcePort"`
	DestinationIP     string `json:"destinationIP"`
	DestinationPort   string `json:"destinationPort"`
	Host              string `json:"host"`
	DNSMode           string `json:"dnsMode"`
	Process           string `json:"process"`
	ProcessPath       string `json:"processPath"`
	SpecialProxy      string `json:"specialProxy"`
	RemoteDestination string `json:"remoteDestination"`
}

type trackedConnectionSnapshot struct {
	ID          string                    `json:"id"`
	Metadata    trackedConnectionMetadata `json:"metadata"`
	Upload      int64                     `json:"upload"`
	Download    int64                     `json:"download"`
	Start       time.Time                 `json:"start"`
	Chains      []string                  `json:"chains"`
	Rule        string                    `json:"rule"`
	RulePayload string                    `json:"rulePayload"`
}

type trackedConnectionsSnapshot struct {
	UploadTotal   int64                       `json:"uploadTotal"`
	DownloadTotal int64                       `json:"downloadTotal"`
	Connections   []trackedConnectionSnapshot `json:"connections"`
}

type trackedConnection struct {
	id       string
	network  string
	source   xnet.Destination
	target   xnet.Destination
	start    time.Time
	cancel   func()
	close    func()
	upload   atomic.Int64
	download atomic.Int64

	mu          sync.RWMutex
	chains      []string
	rule        string
	rulePayload string
}

func (c *trackedConnection) snapshot() trackedConnectionSnapshot {
	c.mu.RLock()
	chains := append([]string(nil), c.chains...)
	rule := c.rule
	rulePayload := c.rulePayload
	target := c.target
	c.mu.RUnlock()

	host, destinationIP, destinationPort := destinationParts(target)
	sourceIP, sourcePort := endpointParts(c.source)
	return trackedConnectionSnapshot{
		ID: c.id,
		Metadata: trackedConnectionMetadata{
			Network:           c.network,
			Type:              "xray",
			SourceIP:          sourceIP,
			SourcePort:        sourcePort,
			DestinationIP:     destinationIP,
			DestinationPort:   destinationPort,
			Host:              host,
			DNSMode:           "normal",
			RemoteDestination: target.NetAddr(),
		},
		Upload:      c.upload.Load(),
		Download:    c.download.Load(),
		Start:       c.start,
		Chains:      chains,
		Rule:        rule,
		RulePayload: rulePayload,
	}
}

func (c *trackedConnection) setRoute(tag string, groupTags []string, rule string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.chains = buildConnectionChains(tag, groupTags)
	c.rule = rule
}

type xrayConnectionTracker struct {
	mu          sync.RWMutex
	connections map[string]*trackedConnection
	uploadTotal atomic.Int64
	downTotal   atomic.Int64
	nextID      atomic.Uint64
}

func newXrayConnectionTracker() *xrayConnectionTracker {
	return &xrayConnectionTracker{
		connections: map[string]*trackedConnection{},
	}
}

func (t *xrayConnectionTracker) join(ctx context.Context, ctxCancel func(), destination xnet.Destination, close func()) *trackedConnection {
	id := strconv.FormatUint(t.nextID.Add(1), 10)
	inbound := session.InboundFromContext(ctx)
	source := xnet.Destination{}
	if inbound != nil {
		source = inbound.Source
	}

	conn := &trackedConnection{
		id:      id,
		network: destination.Network.SystemString(),
		source:  source,
		target:  destination,
		start:   time.Now(),
		cancel:  ctxCancel,
		close:   close,
		chains:  []string{},
	}

	t.mu.Lock()
	t.connections[id] = conn
	t.mu.Unlock()
	return conn
}

func (t *xrayConnectionTracker) leave(id string) {
	t.mu.Lock()
	delete(t.connections, id)
	t.mu.Unlock()
}

func (t *xrayConnectionTracker) addUpload(conn *trackedConnection, n int64) {
	if n <= 0 {
		return
	}
	conn.upload.Add(n)
	t.uploadTotal.Add(n)
}

func (t *xrayConnectionTracker) addDownload(conn *trackedConnection, n int64) {
	if n <= 0 {
		return
	}
	conn.download.Add(n)
	t.downTotal.Add(n)
}

func (t *xrayConnectionTracker) snapshot() trackedConnectionsSnapshot {
	t.mu.RLock()
	connections := make([]trackedConnectionSnapshot, 0, len(t.connections))
	for _, conn := range t.connections {
		connections = append(connections, conn.snapshot())
	}
	t.mu.RUnlock()

	return trackedConnectionsSnapshot{
		UploadTotal:   t.uploadTotal.Load(),
		DownloadTotal: t.downTotal.Load(),
		Connections:   connections,
	}
}

func (t *xrayConnectionTracker) snapshotJSON() string {
	data, err := json.Marshal(t.snapshot())
	if err != nil {
		return `{"uploadTotal":0,"downloadTotal":0,"connections":[]}`
	}
	return string(data)
}

func (t *xrayConnectionTracker) close(id string) bool {
	t.mu.RLock()
	conn := t.connections[id]
	t.mu.RUnlock()
	if conn == nil {
		return false
	}
	if conn.cancel != nil {
		conn.cancel()
	}
	if conn.close != nil {
		conn.close()
	}
	return true
}

func (t *xrayConnectionTracker) closeAll() bool {
	t.mu.RLock()
	connections := make([]*trackedConnection, 0, len(t.connections))
	for _, conn := range t.connections {
		connections = append(connections, conn)
	}
	t.mu.RUnlock()

	for _, conn := range connections {
		if conn.cancel != nil {
			conn.cancel()
		}
		if conn.close != nil {
			conn.close()
		}
	}
	return true
}

func (t *xrayConnectionTracker) reset() bool {
	t.closeAll()
	t.mu.Lock()
	t.connections = map[string]*trackedConnection{}
	t.mu.Unlock()
	t.uploadTotal.Store(0)
	t.downTotal.Store(0)
	return true
}

func (t *xrayConnectionTracker) resetAllState() {
	t.closeAll()
	t.mu.Lock()
	t.connections = map[string]*trackedConnection{}
	t.mu.Unlock()
	t.uploadTotal.Store(0)
	t.downTotal.Store(0)
}

var DefaultConnectionTracker = newXrayConnectionTracker()

func TrackLink(ctx context.Context, cancel func(), destination xnet.Destination, link *transport.Link) (func(string, []string, string), func()) {
	reader := &trackedLinkReader{
		Reader: link.Reader,
	}
	writer := &trackedLinkWriter{
		Writer: link.Writer,
	}
	conn := DefaultConnectionTracker.join(ctx, cancel, destination, func() {
		common.Interrupt(reader)
		common.Interrupt(writer)
	})
	reader.conn = conn
	writer.conn = conn
	link.Reader = reader
	link.Writer = writer

	setRoute := func(tag string, groupTags []string, rule string) {
		conn.setRoute(tag, groupTags, rule)
	}
	done := func() {
		DefaultConnectionTracker.leave(conn.id)
	}
	return setRoute, done
}

func SnapshotConnectionsJSON() string {
	return DefaultConnectionTracker.snapshotJSON()
}

func CloseTrackedConnection(id string) bool {
	return DefaultConnectionTracker.close(id)
}

func CloseTrackedConnections() bool {
	return DefaultConnectionTracker.closeAll()
}

func ResetTrackedConnections() bool {
	return DefaultConnectionTracker.reset()
}

func ResetConnectionTrackerState() {
	DefaultConnectionTracker.resetAllState()
}

type trackedLinkReader struct {
	buf.Reader
	conn *trackedConnection
}

func (r *trackedLinkReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.Reader.ReadMultiBuffer()
	DefaultConnectionTracker.addUpload(r.conn, int64(mb.Len()))
	return mb, err
}

func (r *trackedLinkReader) Interrupt() {
	common.Interrupt(r.Reader)
}

func (r *trackedLinkReader) Close() error {
	return common.Close(r.Reader)
}

type trackedLinkWriter struct {
	buf.Writer
	conn *trackedConnection
}

func (w *trackedLinkWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	DefaultConnectionTracker.addDownload(w.conn, int64(mb.Len()))
	return w.Writer.WriteMultiBuffer(mb)
}

func (w *trackedLinkWriter) Interrupt() {
	common.Interrupt(w.Writer)
}

func (w *trackedLinkWriter) Close() error {
	return common.Close(w.Writer)
}

func buildConnectionChains(tag string, groupTags []string) []string {
	result := make([]string, 0, len(groupTags)+1)
	seen := map[string]struct{}{}
	for _, value := range append([]string{tag}, groupTags...) {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func destinationParts(destination xnet.Destination) (host string, ip string, port string) {
	port = strconv.Itoa(int(destination.Port.Value()))
	if destination.Address == nil {
		return "", "", port
	}
	if destination.Address.Family().IsDomain() {
		return destination.Address.Domain(), "", port
	}
	return "", destination.Address.String(), port
}

func endpointParts(destination xnet.Destination) (ip string, port string) {
	if !destination.IsValid() {
		return "", ""
	}
	port = strconv.Itoa(int(destination.Port.Value()))
	if destination.Address == nil {
		return "", port
	}
	return destination.Address.String(), port
}
