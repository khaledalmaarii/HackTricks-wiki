# Suricata & Iptables cheatsheet

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>!HackTricks</strong></a><strong>!</strong></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Iptables

### Chains

In iptables, lists of rules known as chains are processed sequentially. Among these, three primary chains are universally present, with additional ones like NAT being potentially supported depending on the system's capabilities.

- **Input Chain**: Utilized for managing the behavior of incoming connections.
- **Forward Chain**: Employed for handling incoming connections that are not destined for the local system. This is typical for devices acting as routers, where the data received is meant to be forwarded to another destination. This chain is relevant primarily when the system is involved in routing, NATing, or similar activities.
- **Output Chain**: Dedicated to the regulation of outgoing connections.

These chains ensure the orderly processing of network traffic, allowing for the specification of detailed rules governing the flow of data into, through, and out of a system.
```bash
# Delete all rules
iptables -F

# List all rules
iptables -L
iptables -S

# Block IP addresses & ports
iptables -I INPUT -s ip1,ip2,ip3 -j DROP
iptables -I INPUT -p tcp --dport 443 -j DROP
iptables -I INPUT -s ip1,ip2 -p tcp --dport 443 -j DROP

# String based drop
## Strings are case sensitive (pretty easy to bypass if you want to check an SQLi for example)
iptables -I INPUT -p tcp --dport <port_listening> -m string --algo bm --string '<payload>' -j DROP
iptables -I OUTPUT -p tcp --sport <port_listening> -m string --algo bm --string 'CTF{' -j DROP
## You can also check for the hex, base64 and double base64 of the expected CTF flag chars

# Drop every input port except some
iptables -P INPUT DROP # Default to drop
iptables -I INPUT -p tcp --dport 8000 -j ACCEPT
iptables -I INPUT -p tcp --dport 443 -j ACCEPT


# Persist Iptables
## Debian/Ubuntu:
apt-get install iptables-persistent
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6
iptables-restore < /etc/iptables/rules.v4
##RHEL/CentOS:
iptables-save > /etc/sysconfig/iptables
ip6tables-save > /etc/sysconfig/ip6tables
iptables-restore < /etc/sysconfig/iptables
```
## Suricata

### QaD & Qap

#### QaD

`Suricata` is a free and open-source network intrusion detection system (NIDS) that is capable of inspecting network traffic in real-time. It can detect and alert on various types of malicious activities, such as network scans, malware infections, and suspicious network behavior.

#### Qap

To install `Suricata`, follow these steps:

1. Update the package manager:
   ```
   sudo apt update
   ```

2. Install `Suricata`:
   ```
   sudo apt install suricata
   ```

3. Configure `Suricata` by editing the configuration file located at `/etc/suricata/suricata.yaml`. You can customize various settings, such as network interfaces to monitor, rulesets to use, and logging options.

4. Start `Suricata`:
   ```
   sudo suricata -c /etc/suricata/suricata.yaml -i <interface>
   ```
   Replace `<interface>` with the name of the network interface you want `Suricata` to monitor.

5. Verify that `Suricata` is running:
   ```
   sudo suricata --list-runmodes
   ```
   You should see the output `default` if `Suricata` is running successfully.

### Rule Management

#### Rule Syntax

`Suricata` uses a rule-based language called `Emerging Threats Pro` (ETPro) to define the behavior it should detect. The syntax of a rule is as follows:

```
alert [action] [protocol] [source IP] [source port] [direction] [destination IP] [destination port] ([options])
```

- `action`: The action to take when the rule matches. Common actions include `alert`, `log`, and `drop`.
- `protocol`: The network protocol to match, such as `tcp`, `udp`, or `icmp`.
- `source IP` and `destination IP`: The source and destination IP addresses to match.
- `source port` and `destination port`: The source and destination port numbers to match.
- `direction`: The direction of the network traffic to match, such as `->` for outgoing traffic or `<-` for incoming traffic.
- `options`: Additional options to customize the rule's behavior, such as matching specific payloads or patterns.

#### Rule Management

To manage rules in `Suricata`, follow these steps:

1. Locate the rules directory:
   ```
   cd /etc/suricata/rules
   ```

2. Add or modify rules by editing the rule files in this directory. You can create new rule files or modify existing ones using a text editor.

3. Reload the rules:
   ```
   sudo suricata-update enable-source et/open
   sudo suricata-update update-sources
   sudo suricata-update
   ```

4. Restart `Suricata` to apply the updated rules:
   ```
   sudo systemctl restart suricata
   ```

### Log Analysis

`Suricata` generates log files that contain information about detected events and network traffic. These log files can be analyzed to gain insights into potential security threats.

To analyze `Suricata` log files, you can use tools such as `Elasticsearch`, `Logstash`, and `Kibana` (ELK stack) or `Splunk`. These tools provide powerful search and visualization capabilities for log analysis.

### Iptables Integration

`Suricata` can be integrated with `iptables` to block malicious traffic based on the detected events. This integration allows `Suricata` to act as an intrusion prevention system (IPS).

To integrate `Suricata` with `iptables`, follow these steps:

1. Install `iptables`:
   ```
   sudo apt install iptables
   ```

2. Configure `iptables` rules to redirect traffic to `Suricata`:
   ```
   sudo iptables -A INPUT -j NFQUEUE --queue-num 0
   sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0
   ```

3. Start `Suricata` with the `--af-packet` option to capture traffic from the network interface:
   ```
   sudo suricata -c /etc/suricata/suricata.yaml --af-packet=<interface>
   ```
   Replace `<interface>` with the name of the network interface you want `Suricata` to monitor.

4. Configure `Suricata` to block malicious traffic by adding the following line to the `suricata.yaml` file:
   ```
   iptables-block: yes
   ```

5. Restart `Suricata` to apply the configuration changes:
   ```
   sudo systemctl restart suricata
   ```

Now, `Suricata` will block malicious traffic by adding `iptables` rules to drop or reject the corresponding packets.
```bash
# Install details from: https://suricata.readthedocs.io/en/suricata-6.0.0/install.html#install-binary-packages
# Ubuntu
add-apt-repository ppa:oisf/suricata-stable
apt-get update
apt-get install suricata

# Debian
echo "deb http://http.debian.net/debian buster-backports main" > \
/etc/apt/sources.list.d/backports.list
apt-get update
apt-get install suricata -t buster-backports

# CentOS
yum install epel-release
yum install suricata

# Get rules
suricata-update
suricata-update list-sources #List sources of the rules
suricata-update enable-source et/open #Add et/open rulesets
suricata-update
## To use the dowloaded rules update the following line in /etc/suricata/suricata.yaml
default-rule-path: /var/lib/suricata/rules
rule-files:
- suricata.rules

# Run
## Add rules in /etc/suricata/rules/suricata.rules
systemctl suricata start
suricata -c /etc/suricata/suricata.yaml -i eth0


# Reload rules
suricatasc -c ruleset-reload-nonblocking
## or set the follogin in /etc/suricata/suricata.yaml
detect-engine:
- rule-reload: true

# Validate suricata config
suricata -T -c /etc/suricata/suricata.yaml -v

# Configure suricata as IPs
## Config drop to generate alerts
## Search for the following lines in /etc/suricata/suricata.yaml and remove comments:
- drop:
alerts: yes
flows: all

## Forward all packages to the queue where suricata can act as IPS
iptables -I INPUT -j NFQUEUE
iptables -I OUTPUT -j NFQUEUE

## Start suricata in IPS mode
suricata -c /etc/suricata/suricata.yaml  -q 0
### or modify the service config file as:
systemctl edit suricata.service

[Service]
ExecStart=
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml --pidfile /run/suricata.pid -q 0 -vvv
Type=simple

systemctl daemon-reload
```
### tlhIngan Hol

[latlh ghItlh:](https://github.com/OISF/suricata/blob/master/doc/userguide/rules/intro.rst) ngeD 'oH 'e' vItlhutlh:

* **qap**, 'oH vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vIt
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **Qapmey**

* **qawHaq** - qawHaq 'ej ghItlh
* **QaH** - qawHaq 'ej ghItlh
* **QaH** - qawHaq 'ej ghItlh
* **QaH** - qawHaq 'ej ghItlh
* **QaH** - qawHaq 'ej ghItlh
* **QaH** - qawHaq 'ej ghItlh
* **QaH** - qawHaq 'ej ghItlh

#### **Protocols**

* tcp (tcp-traffic)
* udp
* icmp
* ip (ip stands for 'all' or 'any')
* _layer7 protocols_: http, ftp, tls, smb, dns, ssh... (more in the [**docs**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html))

#### Source 'ej Destination Addresses

vItlhutlh IP ranges, negations 'ej list addresses:

| Example                        | Meaning                                  |
| ------------------------------ | ---------------------------------------- |
| ! 1.1.1.1                      | 1.1.1.1 Hoch 'ej Hoch Hoch                |
| !\[1.1.1.1, 1.1.1.2]           | 1.1.1.1 Hoch 'ej Hoch Hoch                |
| $HOME\_NET                     | yaml HOME\_NET vItlhutlh                  |
| \[$EXTERNAL\_NET, !$HOME\_NET] | EXTERNAL\_NET 'ej Hoch Hoch               |
| \[10.0.0.0/24, !10.0.0.5]      | 10.0.0.0/24 Hoch 10.0.0.5 Hoch            |

#### Source 'ej Destination Ports

vItlhutlh port ranges, negations 'ej list ports

| Example         | Meaning                                |
| --------------- | -------------------------------------- |
| any             | Hoch Hoch                              |
| \[80, 81, 82]   | 80, 81 'ej 82 Hoch                     |
| \[80: 82]       | 80 Hoch 82                             |
| \[1024: ]       | 1024 Hoch Hoch port-number              |
| !80             | 80 Hoch Hoch                           |
| \[80:100,!99]   | 80 Hoch 100 Hoch Hoch 99 Hoch           |
| \[1:80,!\[2,4]] | 1-80 Hoch, Hoch 2 'ej 4 Hoch            |

#### Direction

qawHaq qawHaq rule communication qaptaHvIS jImej:
```
source -> destination
source <> destination  (both directions)
```
#### tlhIngan Hol

**Suricata** vItlhutlh **qetlh** packet **vItlhutlh** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **qawHaq** **q
```bash
# Meta Keywords
msg: "description"; #Set a description to the rule
sid:123 #Set a unique ID to the rule
rev:1 #Rule revision number
config classification: not-suspicious,Not Suspicious Traffic,3 #Classify
reference: url, www.info.com #Reference
priority:1; #Set a priority
metadata: key value, key value; #Extra metadata

# Filter by geolocation
geoip: src,RU;

# ICMP type & Code
itype:<10;
icode:0

# Filter by string
content: "something"
content: |61 61 61| #Hex: AAA
content: "http|3A|//" #Mix string and hex
content: "abc"; nocase; #Case insensitive
reject tcp any any -> any any (msg: "php-rce"; content: "eval"; nocase; metadata: tag php-rce; sid:101; rev: 1;)

# Replaces string
## Content and replace string must have the same length
content:"abc"; replace: "def"
alert tcp any any -> any any (msg: "flag replace"; content: "CTF{a6st"; replace: "CTF{u798"; nocase; sid:100; rev: 1;)
## The replace works in both input and output packets
## But it only modifies the first match

# Filter by regex
pcre:"/<regex>/opts"
pcre:"/NICK .*USA.*[0-9]{3,}/i"
drop tcp any any -> any any (msg:"regex"; pcre:"/CTF\{[\w]{3}/i"; sid:10001;)

# Other examples
## Drop by port
drop tcp any any -> any 8000 (msg:"8000 port"; sid:1000;)
```
<details>

<summary><strong>qaStaHvIS AWS hacking vItlh</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* **Do you work in a** **cybersecurity company**? **Do you want to see your** **company advertised in HackTricks**? **or do you want to have access to the** **latest version of the PEASS or download HackTricks in PDF**? **Check the** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* **Discover** [**The PEASS Family**](https://opensea.io/collection/the-peass-family), **our collection of exclusive** [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Get the** [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) **Discord group**](https://discord.gg/hRep4RUj7f) **or the** [**telegram group**](https://t.me/peass) **or** **follow** **me on** **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)**.**

</details>
