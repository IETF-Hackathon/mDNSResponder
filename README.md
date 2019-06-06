# DNS-Based Service Discovery (DNS-SD)

This repository is used for IETF work on DNS-Based Service Discovery, particularly the DNS-SD Discovery Proxy.

This work is the product of the [IETF DNSSD Working Group](https://datatracker.ietf.org/wg/dnssd/about/).

The specification for the DNS-SD Discovery Proxy can be found in [draft-ietf-dnssd-hybrid](https://tools.ietf.org/html/draft-ietf-dnssd-hybrid).

Other useful background reading includes
[Multicast DNS (RFC 6762)](https://tools.ietf.org/html/rfc6762) and
[DNS-Based Service Discovery (RFC 6763)](https://tools.ietf.org/html/rfc6763).

This code is Open Source under the Apache 2.0 license.

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

## Installing the Prebuilt Package

At the moment prebuilt packages are only available for the router we are using internally for development,
the [GL-iNet AR750S](https://www.gl-inet.com/products/gl-ar750s/).   These packages may also work on routers
with similar configurations.

There are two ways to install the proxy on an OpenWrt device.   These instructions explain how to do it using the command line; we will produce a video that shows how to do it using the user interface.

To install the proxy using the command line, bring up a shell on your Mac, which must be
connected to the OpenWrt device.  The OpenWrt device must have a working Internet connection.
To connect to the router, type:

    ssh 192.168.8.1 -l root

Then enter the password that you configured when you set up the router.   You can also install an ssh key on the router using [the router’s web user interface](http://192.168.8.1/cgi-bin/luci/admin/system/admin).

When you are at a command prompt on the router, install the libustream-mbedtls package, which is needed to do https downloads:

    opkg update
	opkg install libustream-mbedtls mbedtls-utils
	
Now add this line to the end of /etc/opkg/customfeeds.conf:

    src/gz dnssd https://raw.githubusercontent.com/IETF-Hackathon/mDNSResponder/release/OpenWrt/packages/mips_24kc/base

To fetch the new feed, once again:

    opkg update

Now remove the dnsmasq package, since we’re installing a new DNS server:

    opkg remove dnsmasq

Now install the ISC DHCP server, which is needed to provide DNS service now that dnsmasq is no longer present:

    opkg install isc-dhcp-server-ipv4

You will also need to install the mbedtls-write package, which adds an mbedtls utility required to sign the
self-signed cert that dnssd-proxy uses for the TLS connection:

    opkg install mbedtls-write

And finally, install the dnssd-proxy package, which also installs the mDNSResponder package:

    opkg install dnssd-proxy

At this point you can use DNS to discover services on the LAN interface of the OpenWrt router.   Please be aware that there is no firewalling: you should not set this up on your edge router, or else anyone on the Internet will be able to discover services on your LAN.

## Picking a DNS Subdomain Name for your Advertised Services

DNS-Based Service Discovery, is based, naturally enough, on DNS domain names.

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
with an associated DNS hostname,
so that clients can reliably connect to it.

For an initial trial you’ll probably want to start with a single Discovery Proxy
on a single link, to evaluate how well it works for your situation.

In an operational network, for each link you will need a properly delegated subdomain,
delegated (using DNS “NS” records) to the Discovery Proxy on that link,
which acts as the authoritative DNS server for that DNS subdomain name.

For evaluation you can use a temporary name, without it being formally delegated.

If you (or your organization) has a DNS domain name already,
then you can use a subdomain of that name.
If your DNS domain name is “example.org”
then you could use “my-building.example.org”
as the name for the link on which the Discovery Proxy resides.
If you don’t have a suitable domain name you can use,
then you can use “service.home.arpa”
as the name for the link on which the Discovery Proxy resides.

## Configuring and Running the Discovery Proxy

Because the Discovery Proxy uses TLS, a key and certificate are required.
Currently, for testing, self-signed certificates are allowed.

To generate the key and self-signed certificate, use the commands below.
Replace hostname.example.com with the actual hostname of the Discovery Proxy device.

On a linux or MacOS install, you will run the gen_key and cert_write commands from your
home directory (or the directory where you checked out mbedtls).

    $HOME/mbedtls/programs/pkey/gen_key type=rsa rsa_keysize=4096 filename=server.key
    $HOME/mbedtls/programs/x509/cert_write selfsign=1 issuer_key=server.key issuer_name=CN=hostname.example.com not_before=20190226000000 not_after=20211231235959 is_ca=1 max_pathlen=0 output_file=server.crt
    sudo mkdir /etc/dnssd-proxy
    sudo mv server.key server.crt /etc/dnssd-proxy

On OpenWrt, the utilities are installed, so invoke them as follows, again changing hostname.example.com to the correct hostname:

    cd /etc/dnssd-proxy
    gen_key type=rsa rsa_keysize=4096 filename=server.key
    cert_write selfsign=1 issuer_key=server.key issuer_name=CN=hostname.example.com not_before=20190226000000 not_after=20211231235959 is_ca=1 max_pathlen=0 output_file=server.crt

On OpenWrt, generating the key may take a significant amount of time.   Do not interrupt the key generation process.   It’s just sitting there collecting random data, so it will eventually complete.

dnssd-proxy loads the key and certificate from /etc/dnssd-proxy by default.   These can be configured
by adding lines to /etc/dnssd-proxy.cf (see below) specifying, e.g.:

tls-key /my/dir/server.key
tls-cert /my/dir/server.crt

By default dnssd-proxy assumes a self-signed cert; if the cert has
been signed by a ca, the ca cert file should also be provided (this may
contain a certification chain rather than a single certificate):

tls-cacert /my/dir/ca.crt

The dnssd-proxy operation is controlled by the file

	/etc/dnssd-proxy.cf

Create this file with text as illustrated below:

	interface en0 my-building.example.org.
	my-name my-hostname.example.org.
	my-ipv4-addr 203.0.113.123
	udp-port 53
	tcp-port 53
	tls-port 853

Replace “en0” with the name of the interface on which you want the Discovery Proxy to discover services.

To see the list of available interfaces, use the “ifconfig” command.
On a modern Mac there are many.
As a general rule, look for one of the “en” interfaces, where the flags say “UP,BROADCAST,…”

Replace “my-building.example.org.” with your delegated subdomain name,
or “service.home.arpa” if you have no delegated subdomain name.

Replace “my-hostname.example.org” with the DNS hostname of your Discovery Proxy device.

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

If “my-building.example.org” is properly delegated to your Discovery Proxy,
then this is all that is required for client devices to remotely discover
services on the “my-building.example.org” link.

If “my-building.example.org” is not yet delegated to your Discovery Proxy,
or you’re using a temporary name like “service.home.arpa”,
then you’ll need to manually configure your client devices to use
the IP address of your Discovery Proxy as their DNS resolver.
This will cause them to send all of their DNS requests to your Discovery Proxy.
The Discovery Proxy will answer all the DNS requests it is responsible for
(i.e., service discovery requests for “my-building.example.org”,
“service.home.arpa”, or similar)
and forward all others to its own default DNS resolver.

To manually add a DNS resolver on macOS, go to System Preferences, Network.
Select the currently active network interface and click “Advanced…”
Select “DNS” and click “+” under “DNS Servers” to add a new search domain.

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
