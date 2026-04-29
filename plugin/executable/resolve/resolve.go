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
	"strings"

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

type Resolve struct {
	domain   string
	upstream upstream.Upstream
}

// QuickSetup format: <domain> <server>
// server supports UDP (8.8.8.8, 8.8.8.8:53), TCP (tcp://8.8.8.8),
// DoT (tls://8.8.8.8, tls://dns.google), and DoH (https://dns.google/dns-query).
func QuickSetup(_ sequence.BQ, s string) (any, error) {
	fs := strings.Fields(s)
	if len(fs) != 2 {
		return nil, fmt.Errorf("invalid args, expect 2 fields, got %d", len(fs))
	}
	return NewResolve(fs[0], fs[1])
}

// NewResolve creates a new Resolve that resolves domain using server.
// server supports the same address formats as upstream.NewUpstream:
// plain UDP (8.8.8.8 or 8.8.8.8:53), tcp://8.8.8.8, tls://8.8.8.8:853,
// tls://dns.google, https://dns.google/dns-query, etc.
func NewResolve(domain, server string) (*Resolve, error) {
	u, err := upstream.NewUpstream(server, upstream.Opt{})
	if err != nil {
		return nil, fmt.Errorf("failed to init upstream %s: %w", server, err)
	}
	return &Resolve{domain: domain, upstream: u}, nil
}

func (r *Resolve) Close() error {
	return r.upstream.Close()
}

// Exec implements sequence.Executable. It resolves the configured domain using
// the configured server, then sets a response for the current query populated
// with the resolved IPs. Only A and AAAA queries are handled; others are left
// unchanged.
func (r *Resolve) Exec(ctx context.Context, qCtx *query_context.Context) error {
	q := qCtx.Q()
	if len(q.Question) != 1 {
		return nil
	}
	qtype := q.Question[0].Qtype
	if qtype != dns.TypeA && qtype != dns.TypeAAAA {
		return nil
	}

	// Build a query for the configured domain with the same qtype.
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(r.domain), qtype)
	req.RecursionDesired = true

	wire, err := pool.PackBuffer(req)
	if err != nil {
		return fmt.Errorf("resolve: failed to pack query: %w", err)
	}
	defer pool.ReleaseBuf(wire)

	respWire, err := r.upstream.ExchangeContext(ctx, *wire)
	if err != nil {
		return fmt.Errorf("resolve: upstream exchange failed: %w", err)
	}
	defer pool.ReleaseBuf(respWire)

	resp := new(dns.Msg)
	if err := resp.Unpack(*respWire); err != nil {
		return fmt.Errorf("resolve: failed to unpack response: %w", err)
	}

	// Build a response for the original query using the resolved IPs.
	origName := q.Question[0].Name
	reply := new(dns.Msg)
	reply.SetReply(q)

	for _, rr := range resp.Answer {
		switch rr := rr.(type) {
		case *dns.A:
			reply.Answer = append(reply.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   origName,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    rr.Hdr.Ttl,
				},
				A: rr.A,
			})
		case *dns.AAAA:
			reply.Answer = append(reply.Answer, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   origName,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    rr.Hdr.Ttl,
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
