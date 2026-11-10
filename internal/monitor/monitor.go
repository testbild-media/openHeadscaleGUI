// Package monitor collects reachability (pings from the server gateway),
// latency and traffic statistics for all instances, clients, forwards and
// the DERP relay. Data is kept in memory (1 hour at 10 s resolution).
package monitor

import (
	"context"
	"log/slog"
	"math"
	"net/netip"
	"sort"
	"sync"
	"time"

	"tailscale.com/ipn/ipnstate"

	"github.com/testbild-media/openHeadscaleGUI/internal/derp"
	"github.com/testbild-media/openHeadscaleGUI/internal/forward"
	"github.com/testbild-media/openHeadscaleGUI/internal/gateway"
	"github.com/testbild-media/openHeadscaleGUI/internal/headscale"
)

// Sampling parameters.
const (
	SampleInterval = 10 * time.Second
	PingInterval   = 30 * time.Second
	HistoryLen     = 360 // 1h at 10s
	PingHistoryLen = 120 // 1h at 30s
)

// Series is a fixed size ring of samples.
type Series struct {
	vals []float64
	pos  int
	full bool
}

func newSeries(n int) *Series { return &Series{vals: make([]float64, n)} }

func (s *Series) add(v float64) {
	s.vals[s.pos] = v
	s.pos = (s.pos + 1) % len(s.vals)
	if s.pos == 0 {
		s.full = true
	}
}

// Values returns the samples in chronological order.
func (s *Series) Values() []float64 {
	if s == nil {
		return nil
	}
	if !s.full {
		return append([]float64(nil), s.vals[:s.pos]...)
	}
	out := make([]float64, 0, len(s.vals))
	out = append(out, s.vals[s.pos:]...)
	return append(out, s.vals[:s.pos]...)
}

// Source provides the raw data to the monitor.
type Source interface {
	RunningInstances() []int64
	CachedNodes(instanceID int64) []headscale.Node
	GatewayNodeID(instanceID int64) uint64
	PeerStatus(ctx context.Context, instanceID int64) (*ipnstate.Status, error)
	Ping(ctx context.Context, instanceID int64, ip netip.Addr) (*ipnstate.PingResult, error)
	DERPClients() []derp.Client
	DERPStats() derp.Stats
	ForwardCounters() map[int64]forward.Snapshot
}

type nodeState struct {
	// ping
	PingOK      bool
	PingMs      float64
	PingPath    string
	PingErr     string
	PingAt      time.Time
	pingHist    *Series // ms, NaN = failed
	pingTotal   int
	pingSuccess int

	// gateway traffic (WireGuard counters of the gateway peer)
	gwRx, gwTx     int64
	RxRate, TxRate float64
	rxHist, txHist *Series
	LastHandshake  time.Time
	CurAddr        string
	Relay          string

	// DERP relay traffic
	derpRx, derpTx         uint64
	DERPConnected          bool
	DERPRxRate, DERPTxRate float64
	DERPRemote             string

	seen time.Time
}

type instState struct {
	nodes          map[uint64]*nodeState
	rxHist, txHist *Series
	onlineHist     *Series
	RxRate, TxRate float64
}

type fwdState struct {
	in, out         int64
	InRate          float64
	OutRate         float64
	inHist, outHist *Series
}

// Monitor is the metrics collector.
type Monitor struct {
	src Source
	log *slog.Logger

	mu                                   sync.Mutex
	inst                                 map[int64]*instState
	fwd                                  map[int64]*fwdState
	derpRx                               int64
	derpTx                               int64
	derpRxHist, derpTxHist, derpConnHist *Series
	derpRxRate, derpTxRate               float64
	lastSample                           time.Time
}

// New creates a monitor.
func New(src Source, log *slog.Logger) *Monitor {
	return &Monitor{
		src: src, log: log,
		inst:         map[int64]*instState{},
		fwd:          map[int64]*fwdState{},
		derpRxHist:   newSeries(HistoryLen),
		derpTxHist:   newSeries(HistoryLen),
		derpConnHist: newSeries(HistoryLen),
	}
}

// Run starts the sampling loops until ctx is done.
func (m *Monitor) Run(ctx context.Context) {
	go m.pingLoop(ctx)
	t := time.NewTicker(SampleInterval)
	defer t.Stop()
	for {
		m.sample(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (m *Monitor) instLocked(id int64) *instState {
	is := m.inst[id]
	if is == nil {
		is = &instState{
			nodes:      map[uint64]*nodeState{},
			rxHist:     newSeries(HistoryLen),
			txHist:     newSeries(HistoryLen),
			onlineHist: newSeries(HistoryLen),
		}
		m.inst[id] = is
	}
	return is
}

func newNodeState() *nodeState {
	return &nodeState{
		pingHist: newSeries(PingHistoryLen),
		rxHist:   newSeries(HistoryLen),
		txHist:   newSeries(HistoryLen),
	}
}

func (is *instState) node(id uint64) *nodeState {
	ns := is.nodes[id]
	if ns == nil {
		ns = newNodeState()
		is.nodes[id] = ns
	}
	return ns
}

func rate(cur, prev int64, dt float64) float64 {
	if prev == 0 || cur < prev || dt <= 0 {
		return 0
	}
	return float64(cur-prev) / dt
}

func (m *Monitor) sample(ctx context.Context) {
	now := time.Now()
	m.mu.Lock()
	dt := now.Sub(m.lastSample).Seconds()
	if m.lastSample.IsZero() {
		dt = 0
	}
	m.lastSample = now
	m.mu.Unlock()

	// DERP clients by node key
	derpByKey := map[string]derp.Client{}
	for _, c := range m.src.DERPClients() {
		if prev, ok := derpByKey[c.Key]; ok {
			c.RxBytes += prev.RxBytes
			c.TxBytes += prev.TxBytes
		}
		derpByKey[c.Key] = c
	}

	running := m.src.RunningInstances()
	type peerData struct {
		st  *ipnstate.Status
		err error
	}
	peers := map[int64]peerData{}
	for _, id := range running {
		sctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		st, err := m.src.PeerStatus(sctx, id)
		cancel()
		peers[id] = peerData{st, err}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	alive := map[int64]bool{}
	for _, id := range running {
		alive[id] = true
		is := m.instLocked(id)
		nodes := m.src.CachedNodes(id)
		byKey := map[string]uint64{}
		online := 0
		known := map[uint64]bool{}
		for _, n := range nodes {
			byKey[n.NodeKey] = uint64(n.ID)
			known[uint64(n.ID)] = true
			if n.Online {
				online++
			}
		}
		for nid := range is.nodes {
			if !known[nid] {
				delete(is.nodes, nid)
			}
		}
		var sumRx, sumTx float64
		pd := peers[id]
		seenGW := map[uint64]bool{}
		if pd.err == nil && pd.st != nil {
			for _, p := range pd.st.Peer {
				nid, ok := byKey[p.PublicKey.String()]
				if !ok {
					continue
				}
				seenGW[nid] = true
				ns := is.node(nid)
				ns.RxRate = rate(p.RxBytes, ns.gwRx, dt)
				ns.TxRate = rate(p.TxBytes, ns.gwTx, dt)
				ns.gwRx, ns.gwTx = p.RxBytes, p.TxBytes
				ns.LastHandshake = p.LastHandshake
				ns.CurAddr = p.CurAddr
				ns.Relay = p.Relay
				ns.seen = now
				sumRx += ns.RxRate
				sumTx += ns.TxRate
			}
		}
		for _, n := range nodes {
			nid := uint64(n.ID)
			ns := is.node(nid)
			if !seenGW[nid] {
				ns.RxRate, ns.TxRate = 0, 0
			}
			ns.rxHist.add(ns.RxRate)
			ns.txHist.add(ns.TxRate)
			if c, ok := derpByKey[n.NodeKey]; ok {
				ns.DERPRxRate = rate(int64(c.RxBytes), int64(ns.derpRx), dt)
				ns.DERPTxRate = rate(int64(c.TxBytes), int64(ns.derpTx), dt)
				ns.derpRx, ns.derpTx = c.RxBytes, c.TxBytes
				ns.DERPConnected = true
				ns.DERPRemote = c.Remote
			} else {
				ns.DERPConnected = false
				ns.DERPRxRate, ns.DERPTxRate = 0, 0
				ns.derpRx, ns.derpTx = 0, 0
			}
		}
		is.RxRate, is.TxRate = sumRx, sumTx
		is.rxHist.add(sumRx)
		is.txHist.add(sumTx)
		is.onlineHist.add(float64(online))
	}
	for id := range m.inst {
		if !alive[id] {
			delete(m.inst, id)
		}
	}

	// forwards
	fc := m.src.ForwardCounters()
	for id, c := range fc {
		fs := m.fwd[id]
		if fs == nil {
			fs = &fwdState{inHist: newSeries(HistoryLen), outHist: newSeries(HistoryLen)}
			m.fwd[id] = fs
		}
		fs.InRate = rate(c.BytesIn, fs.in, dt)
		fs.OutRate = rate(c.BytesOut, fs.out, dt)
		fs.in, fs.out = c.BytesIn, c.BytesOut
		fs.inHist.add(fs.InRate)
		fs.outHist.add(fs.OutRate)
	}

	// DERP totals
	ds := m.src.DERPStats()
	m.derpRxRate = rate(ds.BytesReceived, m.derpRx, dt)
	m.derpTxRate = rate(ds.BytesSent, m.derpTx, dt)
	m.derpRx, m.derpTx = ds.BytesReceived, ds.BytesSent
	m.derpRxHist.add(m.derpRxRate)
	m.derpTxHist.add(m.derpTxRate)
	m.derpConnHist.add(float64(ds.Connections))
}

func (m *Monitor) pingLoop(ctx context.Context) {
	t := time.NewTicker(PingInterval)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return
	case <-time.After(20 * time.Second): // let clients reconnect after a restart
	}
	for {
		m.pingAll(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// PingNow triggers an immediate ping of one node and returns the result.
func (m *Monitor) PingNow(ctx context.Context, instanceID int64, node headscale.Node) NodeView {
	m.pingNode(ctx, instanceID, node)
	return m.Node(instanceID, uint64(node.ID))
}

func (m *Monitor) pingAll(ctx context.Context) {
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for _, id := range m.src.RunningInstances() {
		gw := m.src.GatewayNodeID(id)
		for _, n := range m.src.CachedNodes(id) {
			// never ping the server's own node(s)
			if uint64(n.ID) == gw || n.UserName() == gateway.SystemUser {
				continue
			}
			if !n.Online {
				m.recordPing(id, uint64(n.ID), nil, "offline (laut Headscale)")
				continue
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(id int64, n headscale.Node) {
				defer wg.Done()
				defer func() { <-sem }()
				m.pingNode(ctx, id, n)
			}(id, n)
		}
	}
	wg.Wait()
}

func (m *Monitor) pingNode(ctx context.Context, instanceID int64, n headscale.Node) {
	ipStr := n.IPv4()
	if ipStr == "" {
		ipStr = n.IPv6()
	}
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		m.recordPing(instanceID, uint64(n.ID), nil, "keine IP")
		return
	}
	pctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	res, err := m.src.Ping(pctx, instanceID, ip)
	cancel()
	if err != nil {
		m.recordPing(instanceID, uint64(n.ID), nil, err.Error())
		return
	}
	if res.Err != "" {
		m.recordPing(instanceID, uint64(n.ID), nil, res.Err)
		return
	}
	m.recordPing(instanceID, uint64(n.ID), res, "")
}

func (m *Monitor) recordPing(instanceID int64, nodeID uint64, res *ipnstate.PingResult, errMsg string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	is := m.instLocked(instanceID)
	ns := is.node(nodeID)
	ns.PingAt = time.Now()
	ns.pingTotal++
	if res == nil {
		ns.PingOK = false
		ns.PingErr = errMsg
		ns.pingHist.add(math.NaN())
		return
	}
	ns.pingSuccess++
	ns.PingOK = true
	ns.PingErr = ""
	ns.PingMs = res.LatencySeconds * 1000
	switch {
	case res.Endpoint != "":
		ns.PingPath = "direkt " + res.Endpoint
	case res.PeerRelay != "":
		ns.PingPath = "Peer-Relay " + res.PeerRelay
	case res.DERPRegionCode != "":
		ns.PingPath = "DERP " + res.DERPRegionCode
	default:
		ns.PingPath = ""
	}
	ns.pingHist.add(ns.PingMs)
}

// ---- views ----

// NodeView is the exported state of one node.
type NodeView struct {
	Known         bool
	PingOK        bool
	PingMs        float64
	PingPath      string
	PingErr       string
	PingAt        time.Time
	PingHistory   []float64
	Availability  float64 // 0..100, -1 = unknown
	RxRate        float64
	TxRate        float64
	RxTotal       int64
	TxTotal       int64
	RxHistory     []float64
	TxHistory     []float64
	LastHandshake time.Time
	CurAddr       string
	Relay         string
	DERPConnected bool
	DERPRxRate    float64
	DERPTxRate    float64
	DERPRemote    string
}

func (ns *nodeState) view() NodeView {
	v := NodeView{
		Known: true, PingOK: ns.PingOK, PingMs: ns.PingMs, PingPath: ns.PingPath, PingErr: ns.PingErr, PingAt: ns.PingAt,
		PingHistory: ns.pingHist.Values(), RxRate: ns.RxRate, TxRate: ns.TxRate, RxTotal: ns.gwRx, TxTotal: ns.gwTx,
		RxHistory: ns.rxHist.Values(), TxHistory: ns.txHist.Values(), LastHandshake: ns.LastHandshake, CurAddr: ns.CurAddr,
		Relay: ns.Relay, DERPConnected: ns.DERPConnected, DERPRxRate: ns.DERPRxRate, DERPTxRate: ns.DERPTxRate,
		DERPRemote: ns.DERPRemote, Availability: -1,
	}
	if ns.pingTotal > 0 {
		v.Availability = 100 * float64(ns.pingSuccess) / float64(ns.pingTotal)
	}
	return v
}

// Node returns the state of one node.
func (m *Monitor) Node(instanceID int64, nodeID uint64) NodeView {
	m.mu.Lock()
	defer m.mu.Unlock()
	is := m.inst[instanceID]
	if is == nil || is.nodes[nodeID] == nil {
		return NodeView{Availability: -1}
	}
	return is.nodes[nodeID].view()
}

// InstanceView is the aggregated state of an instance.
type InstanceView struct {
	RxRate, TxRate float64
	RxHistory      []float64
	TxHistory      []float64
	OnlineHistory  []float64
	Nodes          map[uint64]NodeView
	AvgPingMs      float64
	Reachable      int
	Probed         int
}

// Instance returns the state of an instance.
func (m *Monitor) Instance(id int64) InstanceView {
	m.mu.Lock()
	defer m.mu.Unlock()
	v := InstanceView{Nodes: map[uint64]NodeView{}}
	is := m.inst[id]
	if is == nil {
		return v
	}
	v.RxRate, v.TxRate = is.RxRate, is.TxRate
	v.RxHistory, v.TxHistory, v.OnlineHistory = is.rxHist.Values(), is.txHist.Values(), is.onlineHist.Values()
	var sum float64
	gw := m.src.GatewayNodeID(id)
	for nid, ns := range is.nodes {
		nv := ns.view()
		v.Nodes[nid] = nv
		if nid != gw && !ns.PingAt.IsZero() {
			v.Probed++
			if ns.PingOK {
				v.Reachable++
				sum += ns.PingMs
			}
		}
	}
	if v.Reachable > 0 {
		v.AvgPingMs = sum / float64(v.Reachable)
	}
	return v
}

// ForwardView is the traffic state of a forward.
type ForwardView struct {
	InRate, OutRate float64
	InHistory       []float64
	OutHistory      []float64
}

// Forward returns the traffic state of a forward.
func (m *Monitor) Forward(id int64) ForwardView {
	m.mu.Lock()
	defer m.mu.Unlock()
	fs := m.fwd[id]
	if fs == nil {
		return ForwardView{}
	}
	return ForwardView{InRate: fs.InRate, OutRate: fs.OutRate, InHistory: fs.inHist.Values(), OutHistory: fs.outHist.Values()}
}

// DERPView is the traffic state of the relay.
type DERPView struct {
	RxRate, TxRate float64
	RxHistory      []float64
	TxHistory      []float64
	ConnHistory    []float64
}

// DERP returns the relay traffic state.
func (m *Monitor) DERP() DERPView {
	m.mu.Lock()
	defer m.mu.Unlock()
	return DERPView{
		RxRate: m.derpRxRate, TxRate: m.derpTxRate,
		RxHistory: m.derpRxHist.Values(), TxHistory: m.derpTxHist.Values(), ConnHistory: m.derpConnHist.Values(),
	}
}

// TopTalkers returns the node IDs of an instance sorted by current traffic.
func (v InstanceView) TopTalkers(n int) []uint64 {
	ids := make([]uint64, 0, len(v.Nodes))
	for id := range v.Nodes {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		a, b := v.Nodes[ids[i]], v.Nodes[ids[j]]
		return a.RxRate+a.TxRate+a.DERPRxRate+a.DERPTxRate > b.RxRate+b.TxRate+b.DERPRxRate+b.DERPTxRate
	})
	if len(ids) > n {
		ids = ids[:n]
	}
	return ids
}
