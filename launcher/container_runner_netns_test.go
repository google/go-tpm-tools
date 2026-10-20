//go:build linux

package launcher

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Const for network setup
const (
	hostV4, hostV6 = "192.0.2.1", "2001:db8::1"
	peerV4, peerV6 = "192.0.2.2", "2001:db8::2"
	brV4, brV6     = "172.20.0.1", "fdb6:c4ca:384d:1::1"
	ctrV4, ctrV6   = "172.20.0.2", "fdb6:c4ca:384d:1::2"

	// The IPv4/IPv6 address ranges are the same as the CNI configuration in `/etc/cni/net.d/10-workload.conf`.
	ctrNetV4 = "172.20.0.0/24"
	ctrNetV6 = "fdb6:c4ca:384d:1::/64"
)

// Parsed at package initialization, so a malformed address fails the test binary at startup.
var (
	ctrAddrV4 = netip.MustParseAddr(ctrV4)
	ctrAddrV6 = netip.MustParseAddr(ctrV6)
)

const (
	cmdTimeout  = 5 * time.Second
	requiredEnv = "CS_NETNS_TEST_REQUIRED"
)

// TestOpenPortsNetns runs the iptables/ip6tables rules from openPorts against a real kernel, using
// three network namespaces that mirror a Confidential Space VM running a non-root container:
//
//	[peer] eth0 ── eth0 [host] br0 ── veth0 ── eth0 [container]
//
// - peer: a remote host
// - host: the host VM
// - container: the workload inside the container - in this test, we expose TCP port 443.
// - IP assignment: See the above `const` block.
//
// The host namespace gets the same conditions as COS: IP forwarding on, FORWARD policy DROP,
// and masquerading for the container subnets (`ipMasq` in the CNI configuration).
//
// The test needs root and the ip, iptables, ip6tables, and sysctl binaries. Otherwise, this test is
// skipped otherwise (see skipf).
func TestOpenPortsNetns(t *testing.T) {
	if os.Geteuid() != 0 {
		skipf(t, "requires root to create network namespaces and iptables rules")
	}
	for _, bin := range []string{"ip", "iptables", "ip6tables", "sysctl"} {
		if _, err := exec.LookPath(bin); err != nil {
			skipf(t, "%s not found: %v", bin, err)
		}
	}
	if _, err := os.Stat("/proc/net/if_inet6"); err != nil {
		skipf(t, "IPv6 is not available")
	}

	// Namespace names are unique per process, so leftovers from an aborted run don't collide.
	suffix := fmt.Sprintf("-%d", os.Getpid())
	hostNS, ctrNS, peerNS := "cs-host"+suffix, "cs-ctr"+suffix, "cs-peer"+suffix
	for _, ns := range []string{hostNS, ctrNS, peerNS} {
		run(t, "ip", "netns", "add", ns)
		t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", ns).Run() })
	}

	setup := [][]string{
		// host <-> peer link.
		{"ip", "-n", hostNS, "link", "add", "eth0", "type", "veth", "peer", "name", "eth0", "netns", peerNS},
		// host <-> ctr link, through the bridge.
		{"ip", "-n", hostNS, "link", "add", "br0", "type", "bridge"},
		{"ip", "-n", hostNS, "link", "add", "veth0", "type", "veth", "peer", "name", "eth0", "netns", ctrNS},
		{"ip", "-n", hostNS, "link", "set", "veth0", "master", "br0"},
		// Addresses. nodad skips IPv6 duplicate address detection, so the addresses are usable at once.
		{"ip", "-n", hostNS, "addr", "add", hostV4 + "/24", "dev", "eth0"},
		{"ip", "-n", hostNS, "addr", "add", hostV6 + "/64", "dev", "eth0", "nodad"},
		{"ip", "-n", hostNS, "addr", "add", brV4 + "/24", "dev", "br0"},
		{"ip", "-n", hostNS, "addr", "add", brV6 + "/64", "dev", "br0", "nodad"},
		{"ip", "-n", peerNS, "addr", "add", peerV4 + "/24", "dev", "eth0"},
		{"ip", "-n", peerNS, "addr", "add", peerV6 + "/64", "dev", "eth0", "nodad"},
		{"ip", "-n", ctrNS, "addr", "add", ctrV4 + "/24", "dev", "eth0"},
		{"ip", "-n", ctrNS, "addr", "add", ctrV6 + "/64", "dev", "eth0", "nodad"},
		{"ip", "-n", hostNS, "link", "set", "lo", "up"},
		{"ip", "-n", hostNS, "link", "set", "eth0", "up"},
		{"ip", "-n", hostNS, "link", "set", "br0", "up"},
		{"ip", "-n", hostNS, "link", "set", "veth0", "up"},
		{"ip", "-n", peerNS, "link", "set", "lo", "up"},
		{"ip", "-n", peerNS, "link", "set", "eth0", "up"},
		{"ip", "-n", ctrNS, "link", "set", "lo", "up"},
		{"ip", "-n", ctrNS, "link", "set", "eth0", "up"},
		// The container's default routes point at the bridge, as with the CNI config.
		{"ip", "-n", ctrNS, "route", "add", "default", "via", brV4},
		{"ip", "-n", ctrNS, "-6", "route", "add", "default", "via", brV6},
		// Host conditions as on COS: forwarding on and FORWARD policy DROP.
		{"ip", "netns", "exec", hostNS, "sysctl", "-q", "-w", "net.ipv4.ip_forward=1"},
		{"ip", "netns", "exec", hostNS, "sysctl", "-q", "-w", "net.ipv6.conf.all.forwarding=1"},
		{"ip", "netns", "exec", hostNS, "iptables", "-P", "FORWARD", "DROP"},
		{"ip", "netns", "exec", hostNS, "ip6tables", "-P", "FORWARD", "DROP"},
		// Masquerade the container's outgoing traffic, as the CNI ipMasq option does.
		{"ip", "netns", "exec", hostNS, "iptables", "-t", "nat", "-A", "POSTROUTING", "-s", ctrNetV4, "!", "-d", ctrNetV4, "-j", "MASQUERADE"},
		{"ip", "netns", "exec", hostNS, "ip6tables", "-t", "nat", "-A", "POSTROUTING", "-s", ctrNetV6, "!", "-d", ctrNetV6, "-j", "MASQUERADE"},
	}
	for _, cmd := range setup {
		run(t, cmd[0], cmd[1:]...)
	}

	// The container serves the exposed port. The peer serves the exposed port and another port.
	// Each listener answers with its name, so the checks below can tell which side answered.
	serve(t, netnsPath(ctrNS), ":443", "ctr")
	serve(t, netnsPath(peerNS), ":443", "peer")
	serve(t, netnsPath(peerNS), ":8080", "peer")

	ports := map[string]struct{}{"443/tcp": {}}
	ctrIPs := []netip.Addr{ctrAddrV4, ctrAddrV6}
	ctx, cancel := context.WithTimeout(t.Context(), cmdTimeout)
	defer cancel()

	// Call the real openPorts inside the host namespace, as the launcher does on the VM.
	// Thus, the iptables/ip6tables rules under test are applied to this test's host.
	if err := inNetNS(netnsPath(hostNS), func() error { return openPorts(ctx, ports, ctrIPs) }); err != nil {
		t.Fatalf("openPorts() in the host namespace: %v", err)
	}

	tests := []struct {
		name       string
		srcNS, dst string
		want       string
	}{
		// Ingress: (peer -> host) should be forwarded to the container.
		{
			name:  "ingress IPv4",
			srcNS: peerNS,
			dst:   net.JoinHostPort(hostV4, "443"),
			want:  "ctr",
		},
		{
			name:  "ingress IPv6",
			srcNS: peerNS,
			dst:   net.JoinHostPort(hostV6, "443"),
			want:  "ctr",
		},

		// Egress (non-exposed): (container <--response-- peer) must get through the FORWARD chain.
		{
			name:  "egress IPv4 to non-exposed port",
			srcNS: ctrNS,
			dst:   net.JoinHostPort(peerV4, "8080"),
			want:  "peer",
		},
		{
			name:  "egress IPv6 to non-exposed port",
			srcNS: ctrNS,
			dst:   net.JoinHostPort(peerV6, "8080"),
			want:  "peer",
		},

		// Egress (exposed):
		// * (container -> peer) must reach the peer and not be DNATed back to the container.
		// * (container <--response-- peer) must get through the FORWARD chain.
		{
			name:  "egress IPv4 to exposed port",
			srcNS: ctrNS,
			dst:   net.JoinHostPort(peerV4, "443"),
			want:  "peer",
		},
		{
			name:  "egress IPv6 to exposed port",
			srcNS: ctrNS,
			dst:   net.JoinHostPort(peerV6, "443"),
			want:  "peer",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := dialFrom(netnsPath(tc.srcNS), tc.dst)
			if err != nil {
				t.Fatalf("dial %s from %s: %v", tc.dst, tc.srcNS, err)
			}
			if got != tc.want {
				t.Errorf("dial %s from %s: answered by %q, want %q", tc.dst, tc.srcNS, got, tc.want)
			}
		})
	}
}

// skipf skips the test unless CS_NETNS_TEST_REQUIRED is set, in which case it fails, so CI notices
// when the test environment is broken instead of silently skipping.
func skipf(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv(requiredEnv) != "" {
		t.Fatalf(format, args...)
	}
	t.Skipf(format, args...)
}

func netnsPath(name string) string { return "/run/netns/" + name }

// run runs a setup command and fails the test if it fails.
func run(t *testing.T, name string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), cmdTimeout)
	defer cancel()
	if out, err := exec.CommandContext(ctx, name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}

// inNetNS runs f on a thread that has entered the network namespace at nsPath. Sockets created and
// commands run by f belong to that namespace. The thread stays locked, so Go discards it when f
// returns instead of reusing it for other goroutines.
func inNetNS(nsPath string, f func() error) error {
	rc := make(chan error, 1)
	go func() {
		runtime.LockOSThread() // Lock the current goroutine to this OS thread.
		// Do not call `runtime.UnlockOSThread()` to prevent the thread from being reused.
		// The thread will be terminated when the goroutine exits.
		fd, err := unix.Open(nsPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			rc <- fmt.Errorf("open %s: %w", nsPath, err)
			return
		}
		defer unix.Close(fd)
		if err := unix.Setns(fd, unix.CLONE_NEWNET); err != nil {
			rc <- fmt.Errorf("setns %s: %w", nsPath, err)
			return
		}
		rc <- f()
	}()
	return <-rc
}

// serve listens on addr in the namespace at nsPath and answers every connection with name.
func serve(t *testing.T, nsPath, addr, name string) {
	t.Helper()
	var ln net.Listener
	// Just listen inside the network namespace.
	err := inNetNS(nsPath, func() (err error) {
		ln, err = net.Listen("tcp", addr)
		return err
	})
	if err != nil {
		t.Fatalf("listen on %s in %s: %v", addr, nsPath, err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// Answer with the name for every connection and then close it.
			_, _ = io.WriteString(c, name)
			_ = c.Close()
		}
	}()
}

// dialFrom connects to addr from the namespace at nsPath and returns the listener's answer.
func dialFrom(nsPath, addr string) (string, error) {
	var answer string
	err := inNetNS(nsPath, func() error {
		c, err := net.DialTimeout("tcp", addr, cmdTimeout)
		if err != nil {
			return err
		}
		defer c.Close()
		if err := c.SetDeadline(time.Now().Add(cmdTimeout)); err != nil {
			return err
		}
		b, err := io.ReadAll(c)
		answer = string(b)
		return err
	})
	return answer, err
}
