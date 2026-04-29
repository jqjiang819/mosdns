/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package resolve

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/upstream"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

const PluginType = "resolve"

func init() {
	sequence.MustRegExecQuickSetup(PluginType, QuickSetup)
}

var _ sequence.Executable = (*Resolve)(nil)

type cachedAddrs struct {
	ips       []dns.RR  // A or AAAA records (Hdr.Name is the resolved domain)
	expiresAt time.Time
}

type Resolve struct {
	domain   string
	upstream upstream.Upstream
	ttl      uint32

	mu    sync.Mutex
	cache map[uint16]*cachedAddrs // keyed by dns.TypeA / dns.TypeAAAA
}

const defaultTTL uint32 = 300

// QuickSetup format: <domain> <server> [ttl]
// ttl is optional and defaults to 300 seconds.
// server supports UDP (8.8.8.8, 8.8.8.8:53), TCP (tcp://8.8.8.8),
// DoT (tls://8.8.8.8, tls://dns.google), and DoH (https://dns.google/dns-query).
func QuickSetup(_ sequence.BQ, s string) (any, error) {
	fs := strings.Fields(s)
	if len(fs) < 2 || len(fs) > 3 {
		return nil, fmt.Errorf("invalid args, expect 2 or 3 fields, got %d", len(fs))
	}
	ttl := defaultTTL
	if len(fs) == 3 {
		v, err := strconv.ParseUint(fs[2], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid ttl, %w", err)
		}
		ttl = uint32(v)
	}
	return NewResolve(fs[0], fs[1], ttl)
}

// NewResolve creates a new Resolve that resolves domain using server.
// server supports the same address formats as upstream.NewUpstream:
// plain UDP (8.8.8.8 or 8.8.8.8:53), tcp://8.8.8.8, tls://8.8.8.8:853,
// tls://dns.google, https://dns.google/dns-query, etc.
func NewResolve(domain, server string, ttl uint32) (*Resolve, error) {
	u, err := upstream.NewUpstream(server, upstream.Opt{})
	if err != nil {
		return nil, fmt.Errorf("failed to init upstream %s: %w", server, err)
	}
	return &Resolve{
		domain:   domain,
		upstream: u,
		ttl:      ttl,
		cache:    make(map[uint16]*cachedAddrs),
	}, nil
}

func (r *Resolve) Close() error {
	return r.upstream.Close()
}

// Exec implements sequence.Executable. It resolves the configured domain using
// the configured server, then sets a response for the current query populated
// with the resolved IPs. Results are cached for ttl seconds. Only A and AAAA
// queries are handled; others are left unchanged.
func (r *Resolve) Exec(ctx context.Context, qCtx *query_context.Context) error {
	q := qCtx.Q()
	if len(q.Question) != 1 {
		return nil
	}
	qtype := q.Question[0].Qtype
	if qtype != dns.TypeA && qtype != dns.TypeAAAA {
		return nil
	}

	ips, remainTTL, ok := r.lookupCache(qtype)
	if !ok {
		var err error
		ips, err = r.resolveUpstream(ctx, qtype)
		if err != nil {
			return err
		}
		r.storeCache(qtype, ips)
		remainTTL = r.ttl
	}

	if len(ips) == 0 {
		return nil
	}

	origName := q.Question[0].Name
	reply := new(dns.Msg)
	reply.SetReply(q)

	for _, rr := range ips {
		switch rr := rr.(type) {
		case *dns.A:
			reply.Answer = append(reply.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   origName,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    remainTTL,
				},
				A: rr.A,
			})
		case *dns.AAAA:
			reply.Answer = append(reply.Answer, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   origName,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    remainTTL,
				},
				AAAA: rr.AAAA,
			})
		}
	}

	if len(reply.Answer) > 0 {
		qCtx.SetResponse(reply)
	}
	return nil
}

// lookupCache returns cached IPs and remaining TTL seconds if a valid cache
// entry exists for qtype.
func (r *Resolve) lookupCache(qtype uint16) ([]dns.RR, uint32, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.cache[qtype]
	if !ok {
		return nil, 0, false
	}
	remaining := time.Until(e.expiresAt)
	if remaining <= 0 {
		delete(r.cache, qtype)
		return nil, 0, false
	}
	secs := uint32(remaining.Seconds())
	return e.ips, secs, true
}

// storeCache saves ips for qtype with an expiry of r.ttl seconds from now.
func (r *Resolve) storeCache(qtype uint16, ips []dns.RR) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache[qtype] = &cachedAddrs{
		ips:       ips,
		expiresAt: time.Now().Add(time.Duration(r.ttl) * time.Second),
	}
}

// resolveUpstream issues a DNS query for r.domain to the upstream server and
// returns the A/AAAA records from the answer section.
func (r *Resolve) resolveUpstream(ctx context.Context, qtype uint16) ([]dns.RR, error) {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(r.domain), qtype)
	req.RecursionDesired = true

	wire, err := pool.PackBuffer(req)
	if err != nil {
		return nil, fmt.Errorf("resolve: failed to pack query: %w", err)
	}
	defer pool.ReleaseBuf(wire)

	respWire, err := r.upstream.ExchangeContext(ctx, *wire)
	if err != nil {
		return nil, fmt.Errorf("resolve: upstream exchange failed: %w", err)
	}
	defer pool.ReleaseBuf(respWire)

	resp := new(dns.Msg)
	if err := resp.Unpack(*respWire); err != nil {
		return nil, fmt.Errorf("resolve: failed to unpack response: %w", err)
	}

	var ips []dns.RR
	for _, rr := range resp.Answer {
		switch rr.(type) {
		case *dns.A, *dns.AAAA:
			ips = append(ips, rr)
		}
	}
	return ips, nil
}
