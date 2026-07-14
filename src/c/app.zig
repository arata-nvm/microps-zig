const microps = @import("microps");

const ether = microps.ether;
const ip = microps.ip;
const net = microps.net;
const loopback = microps.driver.loopback;
const ether_tap = microps.platform.driver.ether_tap;
const util = microps.util;

// Scope of Internet host loopback address.
//  - see https://tools.ietf.org/html/rfc5735
const loopback_ip_addr = "127.0.0.1";
const loopback_netmask = "255.0.0.0";

const ether_tap_name = "tap0";
// Scope of EUI-48 Documentation Values.
//  - see https://tools.ietf.org/html/rfc7042
const ether_tap_hw_addr = "00:00:5e:00:53:01";
// Scope of Documentation Address Blocks (TEST-NET-1).
//  - see https://tools.ietf.org/html/rfc5737
const ether_tap_ip_addr = "192.0.2.2";
const ether_tap_netmask = "255.255.255.0";

const default_gateway = "192.0.2.1";

fn setup() !void {
    net.init(.{}) catch |err| {
        util.errorf(@src(), "net.init() failure: {t}", .{err});
        return err;
    };

    {
        const dev = try loopback.init();
        const iface = try ip.IpIface.create(
            try ip.IpAddr.fromString(loopback_ip_addr),
            try ip.IpAddr.fromString(loopback_netmask),
        );
        try ip.registerIface(dev, iface);
    }

    {
        const addr = try ether.EtherAddr.fromString(ether_tap_hw_addr);
        const dev = try ether_tap.init(ether_tap_name, addr);
        const iface = try ip.IpIface.create(
            try ip.IpAddr.fromString(ether_tap_ip_addr),
            try ip.IpAddr.fromString(ether_tap_netmask),
        );
        try ip.registerIface(dev, iface);
        try ip.route.setDefaultGateway(iface, try ip.IpAddr.fromString(default_gateway));
    }

    try net.run();
}

export fn microps_setup() c_int {
    setup() catch |err| {
        util.errorf(@src(), "microps_setup() failure: {t}", .{err});
        return -1;
    };
    return 0;
}

export fn microps_cleanup() c_int {
    net.shutdown() catch |err| {
        util.errorf(@src(), "microps_cleanup() failure: {t}", .{err});
        return -1;
    };
    return 0;
}
