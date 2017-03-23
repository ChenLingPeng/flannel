/*
Copyright 2016 The Gaia Authors All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ipip

import (
	"fmt"
	"net"
	"os/exec"

	"github.com/coreos/flannel/backend"
	"github.com/coreos/flannel/pkg/ip"
	"github.com/coreos/flannel/subnet"
	"github.com/golang/glog"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/context"
)

const (
	BackendType       = "ipip"
	tunnelName        = "tunl0"
	routeCheckRetries = 10
	tunnelMaxMTU      = 1480
)

func init() {
	backend.Register(BackendType, New)
}

type IPIPBackend struct {
	sm       subnet.Manager
	extIface *backend.ExternalInterface
	networks map[string]*network
}

func New(sm subnet.Manager, extIface *backend.ExternalInterface) (backend.Backend, error) {
	if !extIface.ExtAddr.Equal(extIface.IfaceAddr) {
		return nil, fmt.Errorf("your PublicIP differs from interface IP, meaning that probably you're on a NAT, which is not supported by host-gw backend")
	}

	be := &IPIPBackend{
		sm:       sm,
		extIface: extIface,
		networks: make(map[string]*network),
	}

	return be, nil
}

func (_ *IPIPBackend) Run(ctx context.Context) {
	<-ctx.Done()
}

func (be *IPIPBackend) RegisterNetwork(ctx context.Context, netname string, config *subnet.Config) (backend.Network, error) {
	n := &network{
		name:     netname,
		extIface: be.extIface,
		sm:       be.sm,
	}

	attrs := subnet.LeaseAttrs{
		PublicIP:    ip.FromIP(be.extIface.ExtAddr),
		BackendType: BackendType,
	}

	l, err := be.sm.AcquireLease(ctx, netname, &attrs)
	switch err {
	case nil:
		n.lease = l

	case context.Canceled, context.DeadlineExceeded:
		return nil, err

	default:
		return nil, fmt.Errorf("failed to acquire lease: %v", err)
	}
	dev, err := configureIPIPDevice(n.lease)
	if err != nil {
		return nil, err
	}
	n.tunl0 = dev

	/* NB: docker will create the local route to `sn` */

	be.networks[netname] = n

	return n, nil
}

func configureIPIPDevice(lease *subnet.Lease) (*tunnelDev, error) {
	link, err := netlink.LinkByName(tunnelName)
	if err != nil {
		glog.Infof("will try to create %v")
		// run below command will create tunl0 dev. could also use `ip tunnel add tunl0 mode ipip` command
		cmd := exec.Command("ip", "tunnel", "add", tunnelName, "mode", "ipip")
		err := cmd.Run()
		if err != nil {
			glog.Errorf("failed to create tunnel %v: %v", tunnelName, err)
			return nil, err
		}
		link, err = netlink.LinkByName(tunnelName)
		if err != nil {
			glog.Errorf("failed to find tunnel dev %v: %v", tunnelName, err)
			return nil, err
		}
		glog.Infof("create %v success", tunnelName)
	}
	oldMTU := link.Attrs().MTU
	if oldMTU > tunnelMaxMTU {
		glog.Warningf("%v MTU(%v) greater than %v, will reset to 1480", tunnelName, oldMTU, tunnelMaxMTU)
		err := netlink.LinkSetMTU(link, tunnelMaxMTU)
		if err != nil {
			glog.Errorf("failed to set %v MTU to %v: %v", tunnelName, tunnelMaxMTU, err)
			return nil, err
		}
	}
	if link.Attrs().Flags&net.FlagUp == 0 {
		glog.Warningf("%v is not UP, will up it", tunnelName)
		err := netlink.LinkSetUp(link)
		if err != nil {
			glog.Errorf("failed to set %v UP: %v", tunnelName, err)
			return nil, err
		}
	}

	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		glog.Errorf("failed to list addr for dev %v: %v", tunnelName, err)
		return nil, err
	}

	// first IP. if subnet is 172.17.100.1/24, ip will be 172.17.100.0
	newAddr := lease.Subnet.Network().IP.ToIP()
	found := false
	for _, oldAddr := range addrs {
		if oldAddr.IP.Equal(newAddr) {
			found = true
			continue
		}
		glog.Infof("will delete old %v addr %v", tunnelName, oldAddr.IP.String())
		err = netlink.AddrDel(link, &oldAddr)
		if err != nil {
			glog.Errorf("failed to remove old %v addr(%v): %v", tunnelName, oldAddr.IP.String(), err)
			return nil, err
		}
	}
	if !found {
		mask := net.CIDRMask(32, 32)
		ipNet := net.IPNet{
			IP:   newAddr.Mask(mask),
			Mask: mask,
		}
		addr := &netlink.Addr{
			IPNet: &ipNet,
		}
		err = netlink.AddrAdd(link, addr)
		if err != nil {
			glog.Errorf("failed to add %v addr(%v): %v", tunnelName, addr.IP, err)
			return nil, err
		}
	}
	return &tunnelDev{link: link}, nil
}
