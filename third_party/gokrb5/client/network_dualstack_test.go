package client

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

func startUDPTestKDC(t *testing.T, network, host string) string {
	t.Helper()
	conn, err := net.ListenUDP(network, &net.UDPAddr{IP: net.ParseIP(host)})
	if err != nil {
		if network == "udp6" {
			t.Skipf("IPv6 loopback is unavailable: %v", err)
		}
		t.Fatalf("listen UDP KDC: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	go func() {
		buffer := make([]byte, 4096)
		n, remote, err := conn.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		_, _ = conn.WriteToUDP([]byte("kdc-response"), remote)
		_ = n
	}()

	port := conn.LocalAddr().(*net.UDPAddr).Port
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func startTCPTestKDC(t *testing.T, network, host string) string {
	t.Helper()
	listener, err := net.Listen(network, net.JoinHostPort(host, "0"))
	if err != nil {
		if network == "tcp6" {
			t.Skipf("IPv6 loopback is unavailable: %v", err)
		}
		t.Fatalf("listen TCP KDC: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		header := make([]byte, 4)
		if _, err := io.ReadFull(conn, header); err != nil {
			return
		}
		requestSize := binary.BigEndian.Uint32(header)
		request := make([]byte, requestSize)
		if _, err := io.ReadFull(conn, request); err != nil {
			return
		}

		response := []byte("kdc-response")
		binary.BigEndian.PutUint32(header, uint32(len(response)))
		if _, err := conn.Write(header); err != nil {
			return
		}
		_, _ = conn.Write(response)
	}()

	return listener.Addr().String()
}

func TestResolveKDCAddressesExpandsAAndAAAAAndPreservesKDCOrder(t *testing.T) {
	kdcs := map[int]string{
		2: "backup.example.test:88",
		1: "primary.example.test:88",
	}
	lookup := func(_ context.Context, host string) ([]netip.Addr, error) {
		switch host {
		case "primary.example.test":
			return []netip.Addr{
				netip.MustParseAddr("2001:db8::10"),
				netip.MustParseAddr("192.0.2.10"),
			}, nil
		case "backup.example.test":
			return []netip.Addr{
				netip.MustParseAddr("2001:db8::20"),
				netip.MustParseAddr("192.0.2.10"),
			}, nil
		default:
			return nil, fmt.Errorf("unexpected host %q", host)
		}
	}

	addresses, err := resolveKDCAddresses(context.Background(), kdcs, lookup)
	if err != nil {
		t.Fatalf("resolve KDC addresses: %v", err)
	}
	want := []string{
		"[2001:db8::10]:88",
		"192.0.2.10:88",
		"[2001:db8::20]:88",
	}
	if len(addresses) != len(want) {
		t.Fatalf("got %v, want %v", addresses, want)
	}
	for i := range want {
		if addresses[i] != want[i] {
			t.Fatalf("address %d = %q, want %q (all: %v)", i, addresses[i], want[i], addresses)
		}
	}
}

func TestResolveKDCAddressesKeepsReachableKDCWhenAnotherNameFails(t *testing.T) {
	kdcs := map[int]string{
		1: "unresolvable.example.test:88",
		2: "reachable.example.test:88",
	}
	lookup := func(_ context.Context, host string) ([]netip.Addr, error) {
		if host == "unresolvable.example.test" {
			return nil, errors.New("NXDOMAIN")
		}
		return []netip.Addr{netip.MustParseAddr("192.0.2.20")}, nil
	}

	addresses, err := resolveKDCAddresses(context.Background(), kdcs, lookup)
	if err != nil {
		t.Fatalf("one unresolved KDC must not hide another: %v", err)
	}
	if len(addresses) != 1 || addresses[0] != "192.0.2.20:88" {
		t.Fatalf("unexpected KDC candidates: %v", addresses)
	}
}

func TestResolveKDCAddressesDoesNotWaitForStalledKDCLookup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	kdcs := map[int]string{
		1: "slow.example.test:88",
		2: "reachable.example.test:88",
	}
	lookup := func(ctx context.Context, host string) ([]netip.Addr, error) {
		if host == "slow.example.test" {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return []netip.Addr{netip.MustParseAddr("192.0.2.30")}, nil
	}

	started := time.Now()
	addresses, err := resolveKDCAddresses(ctx, kdcs, lookup)
	elapsed := time.Since(started)
	if err != nil {
		t.Fatalf("a stalled KDC lookup must not hide a reachable alternative: %v", err)
	}
	if elapsed > kdcResolutionWindow+500*time.Millisecond {
		t.Fatalf("stalled KDC lookup delayed the resolved alternative: elapsed=%s", elapsed)
	}
	if len(addresses) != 1 || addresses[0] != "192.0.2.30:88" {
		t.Fatalf("unexpected KDC candidates after bounded resolution: %v", addresses)
	}
}

func TestDialSendUDPUsesIPv4WhenIPv6CandidateIsUnavailable(t *testing.T) {
	ipv4 := startUDPTestKDC(t, "udp4", "127.0.0.1")
	_, port, err := net.SplitHostPort(ipv4)
	if err != nil {
		t.Fatal(err)
	}
	kdcs := map[int]string{
		1: net.JoinHostPort("2001:db8::1", port),
		2: ipv4,
	}

	response, err := dialSendUDP(kdcs, []byte("as-req"))
	if err != nil {
		t.Fatalf("UDP should fall back to the reachable IPv4 KDC: %v", err)
	}
	if string(response) != "kdc-response" {
		t.Fatalf("unexpected UDP response %q", response)
	}
}

func TestDialSendUDPSupportsIPv6OnlyKDC(t *testing.T) {
	ipv6 := startUDPTestKDC(t, "udp6", "::1")
	response, err := dialSendUDP(map[int]string{1: ipv6}, []byte("as-req"))
	if err != nil {
		t.Fatalf("IPv6-only UDP KDC failed: %v", err)
	}
	if string(response) != "kdc-response" {
		t.Fatalf("unexpected UDP response %q", response)
	}
}

func TestDialSendTCPUsesIPv4WhenIPv6CandidateIsUnavailable(t *testing.T) {
	ipv4 := startTCPTestKDC(t, "tcp4", "127.0.0.1")
	_, port, err := net.SplitHostPort(ipv4)
	if err != nil {
		t.Fatal(err)
	}
	kdcs := map[int]string{
		1: net.JoinHostPort("2001:db8::1", port),
		2: ipv4,
	}

	response, err := dialSendTCP(kdcs, []byte("as-req"))
	if err != nil {
		t.Fatalf("TCP should fall back to the reachable IPv4 KDC: %v", err)
	}
	if string(response) != "kdc-response" {
		t.Fatalf("unexpected TCP response %q", response)
	}
}

func TestDialSendTCPSupportsIPv6OnlyKDC(t *testing.T) {
	ipv6 := startTCPTestKDC(t, "tcp6", "::1")
	response, err := dialSendTCP(map[int]string{1: ipv6}, []byte("as-req"))
	if err != nil {
		t.Fatalf("IPv6-only TCP KDC failed: %v", err)
	}
	if string(response) != "kdc-response" {
		t.Fatalf("unexpected TCP response %q", response)
	}
}

func TestRaceKDCAddressesUsesOneOverallDeadline(t *testing.T) {
	addresses := []string{
		"[2001:db8::1]:88",
		"192.0.2.1:88",
		"[2001:db8::2]:88",
		"192.0.2.2:88",
		"[2001:db8::3]:88",
		"192.0.2.3:88",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	started := time.Now()
	_, err := raceKDCAddresses(ctx, addresses, func(ctx context.Context, _ string) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	elapsed := time.Since(started)

	if err == nil {
		t.Fatal("all unreachable KDC candidates must fail")
	}
	if elapsed > time.Second {
		t.Fatalf("KDC attempts exceeded the shared deadline: elapsed=%s", elapsed)
	}
}

func TestRaceKDCAddressesStartsAllCandidatesWithinOneSecond(t *testing.T) {
	addresses := []string{
		"[2001:db8::1]:88",
		"192.0.2.1:88",
		"[2001:db8::2]:88",
		"192.0.2.2:88",
		"[2001:db8::3]:88",
		"192.0.2.3:88",
		"[2001:db8::4]:88",
		"192.0.2.4:88",
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{}, len(addresses))
	done := make(chan struct{})
	go func() {
		_, _ = raceKDCAddresses(ctx, addresses, func(ctx context.Context, _ string) ([]byte, error) {
			started <- struct{}{}
			<-ctx.Done()
			return nil, ctx.Err()
		})
		close(done)
	}()

	timer := time.NewTimer(1200 * time.Millisecond)
	defer timer.Stop()
	for range addresses {
		select {
		case <-started:
		case <-timer.C:
			cancel()
			t.Fatal("not all KDC candidates started within the bounded fallback window")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("KDC attempts did not stop after context cancellation")
	}
}
