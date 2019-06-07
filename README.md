# DNS-Based Service Discovery (DNS-SD)

This repository is used for IETF work on DNS-Based Service Discovery, particularly the DNS-SD Discovery Proxy.

This code is Open Source under the Apache 2.0 license.

This work is the product of the IETF [DNSSD](https://datatracker.ietf.org/wg/dnssd/about/) Working Group.

The specification for the DNS-SD Discovery Proxy can be found in
[draft-ietf-dnssd-hybrid](https://tools.ietf.org/html/draft-ietf-dnssd-hybrid).

Other useful background reading includes
[Multicast DNS (RFC 6762)](https://tools.ietf.org/html/rfc6762) and
[DNS-Based Service Discovery (RFC 6763)](https://tools.ietf.org/html/rfc6763).

This work was
[presented at the 2019 Apple Worldwide Developer Conference (WWDC) networking session](https://developer.apple.com/videos/play/wwdc2019/713/).

A very common use case today where a DNS-SD Discovery Proxy is helpful is where
your AirPrint printers are on wired Ethernet,
but your iPhones and iPads are on Wi-Fi,
which is a different link (and a different IPv4 subnet or IPv6 prefix).
In this case, today, your iPhones and iPads on Wi-Fi can’t discover
your AirPrint printers on wired Ethernet, because, by design,
link-local [Multicast DNS](https://tools.ietf.org/html/rfc6762)
does not cross between different links.

By adding a DNS-SD Discovery Proxy on your wired Ethernet,
and arranging for your Wi-Fi clients to add that DNS-SD Discovery Proxy
as an additional DNS-SD (Bonjour) browsing domain,
your Wi-Fi clients will now be able to discover and use those
AirPrint printers on wired Ethernet.

## Target Audience

This sample code is made available for anyone wanting to experiment
with the DNS-SD Discovery Proxy.

However, the intended goal is not that end users and network administrators
build and install their own DNS-SD Discovery Proxies.
The intended goal is that vendors making Wi-Fi Access Points,
routers, and home gateways add this capability to their products.
If you work for one of these vendors, and want to add
DNS-SD Discovery Proxy capability to your products,
please contact us for help about how to do that.

This is pre-release code, and most likely still has some bugs.
If you find bugs please help us improve the code by reporting any bugs you find,
or by suggesting code changes in the form of Git pull requests.

## Building and Operating a DNS-SD Discovery Proxy on your Network

There are four steps to building and operating a DNS-SD Discovery Proxy on your network:

1. Building the Discovery Proxy code and/or installing a prebuilt package.

2. Picking a DNS subdomain name for your advertised services.

3. Configuring and running the Discovery Proxy.

4. Configuring clients with your chosen DNS subdomain name for wide-area discovery.

## Building the Discovery Proxy code

If you want to build this code to run on a Mac or Linux machine, follow the instructions here.
If you just want to run the prebuilt package on an OpenWrt device, you can skip ahead to
“Installing the Prebuilt Package”.

Because this code is targeted at small embedded devices, it uses mbedtls.
If you don’t already have mbedtls installed, you can get it using the following commands:

	git clone https://github.com/ARMmbed/mbedtls
	make
	sudo make install

Clone this Git repository:

	git clone --branch release https://github.com/IETF-Hackathon/mDNSResponder.git

Within your cloned copy of the repository,
change directory to “mDNSResponder/ServiceRegistration” and type “make”.

In the “build” subdirectory this will create the dnssd-proxy executable.

## Installing the Prebuilt Package for OpenWrt

At the moment prebuilt packages are only available for the router we are using internally for development,
the [GL-iNet AR750S](https://www.gl-inet.com/products/gl-ar750s/).
These packages may also work on routers with similar configurations.

There are two ways to install the proxy on an OpenWrt device.
These instructions explain how to do it using the command line;
we will produce a video that shows how to do it using the user interface.

To install the proxy using the command line, bring up a Terminal window on your Mac, which must be
connected to the OpenWrt device.  The OpenWrt device must have a working Internet connection.
To connect to the router, type:

    ssh 192.168.8.1 -l root

Then enter the admin password that you configured when you set up the router.
You can also install an ssh key on the router using
[the router’s web user interface](http://192.168.8.1/cgi-bin/luci/admin/system/admin).

When you are at a command prompt on the router, install the libustream-mbedtls and mbedtls-util packages,
to enable secure https package downloads:

	opkg update
	opkg install libustream-mbedtls mbedtls-util
	
Now add a line to the end of /etc/opkg/customfeeds.conf to add our OpenWrt package, as shown below:

    echo 'src/gz dnssd https://raw.githubusercontent.com/IETF-Hackathon/mDNSResponder/release/OpenWrt/packages/mips_24kc/base' >> /etc/opkg/customfeeds.conf

To fetch the new feed, once again:

    opkg update

Now remove the dnsmasq package, since we’re installing a new DNS server:

    opkg remove dnsmasq

Now install the ISC DHCP server,
which is needed to provide DHCP service now that dnsmasq is no longer present,
the mbedtls-write package, and dnssd-proxy package, which also installs the mDNSResponder package:

    opkg install isc-dhcp-server-ipv4 mbedtls-write dnssd-proxy

At this point you are ready to continue with configuring your Discovery Proxy.

## Picking a DNS Subdomain Name for your Advertised Services

DNS-Based Service Discovery, is based, naturally enough, on DNS domain names.

Two DNS domain names are involved here,
the DNS name for the advertised link, and
the DNS hostname for the Discovery Proxy doing the advertising.
These two names are different.

For each physical (or virtual) link
on your network for which you wish to enable remote discovery of services
you need to chose a DNS domain name,
much like how you choose and assign domain names to individual hosts.
In this context the term “link” means an IP multicast domain —
a group of devices that can all communicate with each other using IP multicast,
which is used by [Multicast DNS](https://tools.ietf.org/html/rfc6762).

On each of the links
on your network for which you wish to enable remote discovery of services
you install a Discovery Proxy, to perform discovery operations on behalf of remote clients.
The Discovery Proxy should be assigned a static IP address,
so that clients can reliably connect to it.

For an initial trial you’ll probably want to start with a single Discovery Proxy
on a single link, to evaluate how well it works for your situation.

In an operational network, for each link you will need a properly delegated subdomain,
delegated (using DNS “NS” records) to the Discovery Proxy on that link,
which acts as the authoritative DNS server for that DNS subdomain name.
To delegate the link name subdomain to the appropriate Discovery Proxy,
the Discovery Proxy device needs a DNS hostname, to go in the delegating DNS “NS” record.
You can run a Discovery Proxy without a DNS hostname,
but in this case you will not be able to use DNS delegation,
and clients will have to be configured with the IP address of the Discovery Proxy,
as explained below in the section “Manually adding a DNS resolver address”.
If you don’t have a DNS hostname for your Discovery Proxy device,
then where these instructions talk about the hostname, you can use the name
“discoveryproxy.home.arpa” instead.

For evaluation you can use a temporary name for the link, without it being formally delegated.

If you (or your organization) has a DNS domain name already,
then you can use a subdomain of that name for the link.
If your DNS domain name is “example.org”
then you could use “my-building.example.org”
as the name for the link on which the Discovery Proxy resides.
For testing, it is okay if this link subdomain name is not formally delegated to your Discovery Proxy.
If you don’t have a suitable domain name you can use,
then you can use “service.home.arpa”
as the name for the link on which the Discovery Proxy resides.

To recap:
two DNS domain names are involved here,
the DNS name for the advertised link, and
the DNS hostname for the Discovery Proxy doing the advertising.
These two names are different.
One names the advertised link; the other names the device doing the advertising.
By default the names for testing are:

	Link name: service.home.arpa
	Discovery Proxy hostname: discoveryproxy.home.arpa

## Configuring and Running the Discovery Proxy

Because the Discovery Proxy uses TLS, a key and certificate are required.
Currently, for testing, self-signed certificates are allowed.

To generate the key and self-signed certificate, use the commands below.
Replace the hostname discoveryproxy.home.arpa with the actual hostname of the Discovery Proxy device, if you have one.

On a linux or MacOS install, you will run the gen_key and cert_write commands:

    $HOME/mbedtls/programs/pkey/gen_key type=rsa rsa_keysize=4096 filename=server.key
    $HOME/mbedtls/programs/x509/cert_write selfsign=1 issuer_key=server.key issuer_name=CN=discoveryproxy.home.arpa not_before=20190226000000 not_after=20211231235959 is_ca=1 max_pathlen=0 output_file=server.crt
    sudo mkdir /etc/dnssd-proxy
    sudo mv server.key server.crt /etc/dnssd-proxy

On OpenWrt, the utilities are installed, so invoke them as follows, again changing discoveryproxy.home.arpa to the correct hostname:

    cd /etc/dnssd-proxy
    gen_key type=rsa rsa_keysize=4096 filename=server.key
    cert_write selfsign=1 issuer_key=server.key issuer_name=CN=discoveryproxy.home.arpa not_before=20190226000000 not_after=20211231235959 is_ca=1 max_pathlen=0 output_file=server.crt

On OpenWrt, generating the key may take as much as 3 minutes.
Do not interrupt the key generation process.
It’s just sitting there collecting random data, so it will eventually complete.

The dnssd-proxy operation is controlled by the file

	/etc/dnssd-proxy.cf

If running on Linux or Mac, create this file with text as illustrated below:

	interface en0 service.home.arpa.
	my-name discoveryproxy.home.arpa.
	my-ipv4-addr 203.0.113.123
	udp-port 53
	tcp-port 53
	tls-port 853

Replace “en0” with the name of the interface on which you want the Discovery Proxy to discover services.

To see the list of available interfaces, use the “ifconfig” command.
On a modern Mac there are many.
As a general rule, look for one of the “en” interfaces, where the flags say “UP,BROADCAST,…”

If you have a subdomain name for the link,
replace “service.home.arpa” with that subdomain name.

If your Discovery Proxy device has a DNS hostname,
replace “discoveryproxy.home.arpa” with that DNS hostname.
This is not necessary when running on the OpenWrt router,
because the router automatically configures its hostname
as "ns.service.home.arpa."   On OpenWRT on the AR-750S, in order to enable
service discovery on the WAN port, you may type the following:

	uci set glfw.@opening[0].port='5353'
	uci set glfw.@opening[0].name='mDNS'
	uci set glfw.@opening[0].proto='UDP'
	uci set glfw.@opening[0].status='Enabled'
	uci commit

It may be necessary to restart the router after doing this (type "reboot").

Replace “203.0.113.123” with the actual IP address of your Discovery Proxy device.

Once you have the key, the certificate, and the configuration file in place,
run the dnssd-proxy executable in a Terminal window.

You should see some lines beginning “hardwired_add”,
followed by “waiting” when the dnssd-proxy is ready to start processing requests.

## Configuring Clients with Your Chosen DNS Subdomain Name for Wide-Area Discovery

This Discovery Proxy, built using
[DNS Stateful Operations](https://tools.ietf.org/html/rfc8490) and
[DNS Push Notifications](https://tools.ietf.org/html/draft-ietf-dnssd-push),
can be used with the current Apple developer seeds of iOS 13 and macOS Catalina.
Older versions of iOS and macOS do not include support for
DNS Stateful Operations and DNS Push Notifications.

The client needs to be told in which DNS domains to look for services,
in addition to “local”
([Multicast DNS](https://tools.ietf.org/html/rfc6762) on the local link).

In an operational network, this configuration is performed automatically,
by adding special DNS records.
If your network’s DHCP server configures your client devices
with a “domain” parameter of “example.org”,
then the following DNS record will automatically inform those client devices
to look for services in “my-building.example.org”.
No manual client configuration is required.

	lb._dns-sd._udp.example.org. PTR my-building.example.org.

There are other ways that automatic configuration can be performed, described in
[Section 11 of RFC 6763](https://tools.ietf.org/html/rfc6763#section-11).

On OpenWrt, the domain can be configured as follows:

	uci set dhcp.isc_dhcpd.domain="service.home.arpa"
	/etc/init.d/dhcpd restart

If you are using the default configuration as we have described earlier, this will
configure the correct domain; if you are using a different domain, that domain is
the correct one to specify in this command, rather than service.home.arpa.
You may need to disconnect from and reassociate with the router's Wifi network to
get the new setting.

In an operational network, no client configuration is required.
It is all completely automatic.
However, for testing, unless you have the necessary DNS records created,
you can simulate this via some manual client configuration.

### Manually adding a DNS search domain on the client, for testing

If you don’t have the ability at this time to add a PTR record to your
organization’s existing DNS server, then for evaluation you can manually add
“my-building.example.org” (or “service.home.arpa”, or whatever name you chose)
as a DNS search domain on your client devices.

To manually add a DNS search domain on macOS, go to System Preferences, Network.
Select the currently active network interface and click “Advanced…”
Select “DNS” and click “+” under “Search Domains” to add a new search domain.

To manually add a DNS search domain on iOS, go to Settings, Wi-Fi.
Tap on the “i” button, Configure DNS, Manual, and then tap “Add Search Domain”.

### Manually adding a DNS resolver address on the client, for testing

If “my-building.example.org” is properly delegated to your Discovery Proxy
using the appropriate “NS” record,
then this is all that is required for client devices to remotely discover
services on the “my-building.example.org” link.

If “my-building.example.org” is not yet delegated to your Discovery Proxy,
or you’re using a temporary name like “service.home.arpa”,
then instead you’ll need to manually configure your client devices to use
the IP address of your Discovery Proxy as their DNS resolver.
This will cause them to send all of their DNS requests to your Discovery Proxy.
The Discovery Proxy will answer all the DNS requests it is responsible for
(e.g., service discovery requests for “my-building.example.org”,
“service.home.arpa”, or similar)
and forward all others to its own default DNS resolver.

To manually add a DNS resolver on macOS, go to System Preferences, Network.
Select the currently active network interface and click “Advanced…”
Select “DNS”, click “+” under “DNS Servers” and enter the IP address of your Discovery Proxy.

To manually add a DNS resolver on iOS, go to Settings, Wi-Fi.
Tap on the “i” button, Configure DNS, Manual.
Under “DNS SERVERS” delete the servers listed there,
and manually add the IP address of your Discovery Proxy.

## Testing

At this point your clients should be able to discover
services on the remote link, even when they’re not directly connected to that link.

If you have AirPrint printers on the Discovery Proxy link, then remote clients
should be able to discover those and (firewall policy permitting) print on them.

If you have Macs on the Discovery Proxy link with Remote Login enabled,
then on other Macs, when you press Cmd-Shift-K in Terminal, you should
discover those advertised ssh services, even when not directly connected to that link.

## Support

For help with getting this working, please post questions on the
[Apple Developer Forum networking page](https://forums.developer.apple.com/community/core-os/networking).

For discussion of the protocol design, and to get involved with its ongoing development,
please join the IETF
[DNSSD](https://datatracker.ietf.org/wg/dnssd/about/) Working Group’s
[email list](https://www.ietf.org/mailman/listinfo/dnssd).

Even if you have no problems setting up a Discovery Proxy,
if you find the Discovery Proxy useful and would like to see it
appear in commercial Wi-Fi Access Points, routers, and home gateways,
please send a quick email to the DNSSD email list saying that.
These implementation and deployment reports are very valuable
for us to assess the interest the interest in this work and to
guide its future development.
