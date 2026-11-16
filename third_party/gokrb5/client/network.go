package client

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/messages"
)

// SendToKDC performs network actions to send data to the KDC.
func (cl *Client) sendToKDC(b []byte, realm string) ([]byte, error) {
	var rb []byte
	if cl.Config.LibDefaults.UDPPreferenceLimit == 1 {
		//1 means we should always use TCP
		rb, errtcp := cl.sendKDCTCP(realm, b)
		if errtcp != nil {
			if e, ok := errtcp.(messages.KRBError); ok {
				return rb, e
			}
			return rb, fmt.Errorf("communication error with KDC via TCP: %v", errtcp)
		}
		return rb, nil
	}
	if len(b) <= cl.Config.LibDefaults.UDPPreferenceLimit {
		//Try UDP first, TCP second
		rb, errudp := cl.sendKDCUDP(realm, b)
		if errudp != nil {
			if e, ok := errudp.(messages.KRBError); ok && e.ErrorCode != errorcode.KRB_ERR_RESPONSE_TOO_BIG {
				// Got a KRBError from KDC
				// If this is not a KRB_ERR_RESPONSE_TOO_BIG we will return immediately otherwise will try TCP.
				return rb, e
			}
			// Try TCP
			r, errtcp := cl.sendKDCTCP(realm, b)
			if errtcp != nil {
				if e, ok := errtcp.(messages.KRBError); ok {
					// Got a KRBError
					return r, e
				}
				return r, fmt.Errorf("failed to communicate with KDC. Attempts made with UDP (%v) and then TCP (%v)", errudp, errtcp)
			}
			rb = r
		}
		return rb, nil
	}
	//Try TCP first, UDP second
	rb, errtcp := cl.sendKDCTCP(realm, b)
	if errtcp != nil {
		if e, ok := errtcp.(messages.KRBError); ok {
			// Got a KRBError from KDC so returning and not trying UDP.
			return rb, e
		}
		rb, errudp := cl.sendKDCUDP(realm, b)
		if errudp != nil {
			if e, ok := errudp.(messages.KRBError); ok {
				// Got a KRBError
				return rb, e
			}
			return rb, fmt.Errorf("failed to communicate with KDC. Attempts made with TCP (%v) and then UDP (%v)", errtcp, errudp)
		}
	}
	return rb, nil
}

// sendKDCUDP sends bytes to the KDC via UDP.
func (cl *Client) sendKDCUDP(realm string, b []byte) ([]byte, error) {
	var r []byte
	_, kdcs, err := cl.Config.GetKDCs(realm, false)
	if err != nil {
		return r, err
	}
	r, err = dialSendUDP(kdcs, b)
	if err != nil {
		return r, err
	}
	return checkForKRBError(r)
}

const (
	kdcNetworkTimeout   = 5 * time.Second
	kdcResolutionWindow = 1 * time.Second
	kdcFallbackDelay    = 250 * time.Millisecond
	kdcFallbackWindow   = 1 * time.Second
)

type kdcLookupFunc func(context.Context, string) ([]netip.Addr, error)

type kdcLookupResult struct {
	index     int
	addresses []string
	err       error
}

type kdcAttemptResult struct {
	address  string
	response []byte
	err      error
}

// resolveKDCAddresses expands every configured KDC hostname into all of its
// A and AAAA addresses. DNS lookups run concurrently and preserve the
// configured KDC preference order in the returned candidate list.
func resolveKDCAddresses(ctx context.Context, kdcs map[int]string, lookup kdcLookupFunc) ([]string, error) {
	if lookup == nil {
		lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}

	indexes := make([]int, 0, len(kdcs))
	for index := range kdcs {
		indexes = append(indexes, index)
	}
	sort.Ints(indexes)
	if len(indexes) == 0 {
		return nil, fmt.Errorf("no KDCs are configured")
	}

	resolutionCtx, cancelResolution := context.WithTimeout(ctx, kdcResolutionWindow)
	defer cancelResolution()

	results := make(chan kdcLookupResult, len(indexes))
	for _, index := range indexes {
		index := index
		go func() {
			host, port, err := net.SplitHostPort(kdcs[index])
			if err != nil {
				results <- kdcLookupResult{index: index, err: fmt.Errorf("invalid KDC address %q: %w", kdcs[index], err)}
				return
			}
			portNumber, err := strconv.Atoi(port)
			if err != nil || portNumber < 1 || portNumber > 65535 {
				results <- kdcLookupResult{index: index, err: fmt.Errorf("invalid KDC port %q in %q", port, kdcs[index])}
				return
			}

			var ips []netip.Addr
			if ip, parseErr := netip.ParseAddr(host); parseErr == nil {
				ips = []netip.Addr{ip}
			} else {
				ips, err = lookup(resolutionCtx, host)
				if err != nil {
					results <- kdcLookupResult{index: index, err: fmt.Errorf("resolve KDC %q: %w", host, err)}
					return
				}
			}

			addresses := make([]string, 0, len(ips))
			for _, ip := range ips {
				if !ip.IsValid() {
					continue
				}
				addresses = append(addresses, net.JoinHostPort(ip.Unmap().String(), port))
			}
			if len(addresses) == 0 {
				results <- kdcLookupResult{index: index, err: fmt.Errorf("KDC %q has no A or AAAA addresses", host)}
				return
			}
			results <- kdcLookupResult{index: index, addresses: addresses}
		}()
	}

	byIndex := make(map[int]kdcLookupResult, len(indexes))
	remaining := len(indexes)
	for remaining > 0 {
		select {
		case result := <-results:
			byIndex[result.index] = result
			remaining--
		case <-resolutionCtx.Done():
			if err := ctx.Err(); err != nil {
				return nil, fmt.Errorf("KDC address resolution exceeded its overall deadline: %w", err)
			}
			remaining = 0
		}
	}

	// Collect any results that completed at the same time as the bounded
	// resolution window. A stalled KDC lookup must not block a different KDC
	// whose addresses have already resolved.
drainResults:
	for {
		select {
		case result := <-results:
			if _, exists := byIndex[result.index]; !exists {
				byIndex[result.index] = result
			}
		default:
			break drainResults
		}
	}

	addresses := make([]string, 0, len(indexes)*2)
	seen := make(map[string]struct{})
	var lookupErrors []string
	for _, index := range indexes {
		result, resolved := byIndex[index]
		if !resolved {
			lookupErrors = append(lookupErrors, fmt.Sprintf("KDC %q resolution exceeded %s window", kdcs[index], kdcResolutionWindow))
			continue
		}
		if result.err != nil {
			lookupErrors = append(lookupErrors, result.err.Error())
			continue
		}
		for _, address := range result.addresses {
			if _, exists := seen[address]; exists {
				continue
			}
			seen[address] = struct{}{}
			addresses = append(addresses, address)
		}
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("could not resolve any KDC address: %s", strings.Join(lookupErrors, "; "))
	}
	return addresses, nil
}

// raceKDCAddresses starts address attempts with a short stagger. The first
// valid response wins; all attempts share one overall deadline instead of
// paying a separate five-second timeout for every address and KDC.
func raceKDCAddresses(ctx context.Context, addresses []string, attempt func(context.Context, string) ([]byte, error)) ([]byte, error) {
	if len(addresses) == 0 {
		return nil, fmt.Errorf("no resolved KDC addresses")
	}

	attemptCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan kdcAttemptResult, len(addresses))
	stagger := kdcFallbackDelay
	if len(addresses) > 1 && time.Duration(len(addresses)-1)*stagger > kdcFallbackWindow {
		stagger = kdcFallbackWindow / time.Duration(len(addresses)-1)
	}
	for index, address := range addresses {
		index, address := index, address
		go func() {
			if delay := time.Duration(index) * stagger; delay > 0 {
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-attemptCtx.Done():
					return
				case <-timer.C:
				}
			}
			response, err := attempt(attemptCtx, address)
			select {
			case results <- kdcAttemptResult{address: address, response: response, err: err}:
			case <-attemptCtx.Done():
			}
		}()
	}

	var attemptErrors []string
	completed := 0
	for completed < len(addresses) {
		select {
		case result := <-results:
			completed++
			if result.err == nil {
				cancel()
				return result.response, nil
			}
			attemptErrors = append(attemptErrors, fmt.Sprintf("%s: %v", result.address, result.err))
		case <-ctx.Done():
			return nil, fmt.Errorf("KDC address attempts exceeded their overall deadline: %s: %w", strings.Join(attemptErrors, "; "), ctx.Err())
		}
	}
	return nil, fmt.Errorf("all KDC addresses failed: %s", strings.Join(attemptErrors, "; "))
}

func closeConnectionOnContextDone(ctx context.Context, conn net.Conn) func() {
	finished := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-finished:
		}
	}()
	return func() { close(finished) }
}

// dialSendUDP establishes a UDP connection to any configured KDC address.
// A and AAAA candidates are attempted with a staggered fallback and one
// five-second deadline shared by DNS resolution and all network attempts.
func dialSendUDP(kdcs map[int]string, b []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), kdcNetworkTimeout)
	defer cancel()
	addresses, err := resolveKDCAddresses(ctx, kdcs, nil)
	if err != nil {
		return nil, err
	}
	return raceKDCAddresses(ctx, addresses, func(ctx context.Context, address string) ([]byte, error) {
		return sendUDPToKDC(ctx, address, b)
	})
}

func sendUDPToKDC(ctx context.Context, address string, b []byte) ([]byte, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp", address)
	if err != nil {
		return nil, err
	}
	stopClose := closeConnectionOnContextDone(ctx, conn)
	defer stopClose()
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("set UDP KDC deadline: %w", err)
		}
	}
	if _, err := conn.Write(b); err != nil {
		return nil, fmt.Errorf("send UDP request to %s: %w", address, err)
	}
	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		return nil, fmt.Errorf("read UDP response from %s: %w", address, err)
	}
	if n == 0 {
		return nil, fmt.Errorf("no response data from %s", address)
	}
	return response[:n], nil
}

// sendKDCTCP sends bytes to the KDC via TCP.
func (cl *Client) sendKDCTCP(realm string, b []byte) ([]byte, error) {
	var r []byte
	_, kdcs, err := cl.Config.GetKDCs(realm, true)
	if err != nil {
		return r, err
	}
	r, err = dialSendTCP(kdcs, b)
	if err != nil {
		return r, err
	}
	return checkForKRBError(r)
}

// dialSendTCP establishes a TCP connection to any configured KDC address.
// Each candidate has the same overall deadline, so KDC failover cannot
// accumulate one five-second timeout per address or server.
func dialSendTCP(kdcs map[int]string, b []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), kdcNetworkTimeout)
	defer cancel()
	addresses, err := resolveKDCAddresses(ctx, kdcs, nil)
	if err != nil {
		return nil, err
	}
	return raceKDCAddresses(ctx, addresses, func(ctx context.Context, address string) ([]byte, error) {
		return sendTCPToKDC(ctx, address, b)
	})
}

func sendTCPToKDC(ctx context.Context, address string, b []byte) ([]byte, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	stopClose := closeConnectionOnContextDone(ctx, conn)
	defer stopClose()
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("set TCP KDC deadline: %w", err)
		}
	}
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, fmt.Errorf("unexpected TCP connection type %T", conn)
	}
	return sendTCP(tcpConn, b)
}

// sendTCP sends bytes to connection over TCP.
func sendTCP(conn *net.TCPConn, b []byte) ([]byte, error) {
	defer conn.Close()
	var r []byte
	// RFC 4120 7.2.2 specifies the first 4 bytes indicate the length of the message in big endian order.
	hb := make([]byte, 4, 4)
	binary.BigEndian.PutUint32(hb, uint32(len(b)))
	b = append(hb, b...)

	_, err := conn.Write(b)
	if err != nil {
		return r, fmt.Errorf("error sending to KDC (%s): %v", conn.RemoteAddr().String(), err)
	}

	sh := make([]byte, 4, 4)
	_, err = conn.Read(sh)
	if err != nil {
		return r, fmt.Errorf("error reading response size header: %v", err)
	}
	s := binary.BigEndian.Uint32(sh)

	rb := make([]byte, s, s)
	_, err = io.ReadFull(conn, rb)
	if err != nil {
		return r, fmt.Errorf("error reading response: %v", err)
	}
	if len(rb) < 1 {
		return r, fmt.Errorf("no response data from KDC %s", conn.RemoteAddr().String())
	}
	return rb, nil
}

// checkForKRBError checks if the response bytes from the KDC are a KRBError.
func checkForKRBError(b []byte) ([]byte, error) {
	var KRBErr messages.KRBError
	if err := KRBErr.Unmarshal(b); err == nil {
		return b, KRBErr
	}
	return b, nil
}
