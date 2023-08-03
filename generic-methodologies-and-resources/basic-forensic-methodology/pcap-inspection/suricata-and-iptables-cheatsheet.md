# Suricata & Iptables速查表

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>

## Iptables

### 链

Iptables链只是按顺序处理的规则列表。你总是会找到以下3个链，但也可能支持其他链，如NAT。

* **Input** - 此链用于控制传入连接的行为。
* **Forward** - 此链用于未被本地传递的传入连接。想象一个路由器 - 数据总是被发送到它，但很少实际上是目标路由器本身；数据只是被转发到目标。除非你在系统上进行某种路由、NAT或其他需要转发的操作，否则你甚至不会使用此链。
* **Output** - 此链用于传出连接。
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

### 安装和配置

To install Suricata, follow these steps:

1. Update the package manager: `sudo apt update`
2. Install Suricata: `sudo apt install suricata`
3. Verify the installation: `suricata --version`

Once Suricata is installed, you need to configure it. The configuration file is located at `/etc/suricata/suricata.yaml`. Open the file using a text editor and make the necessary changes.

Here are some important configuration options:

- `HOME_NET`: Set the IP address range of your network.
- `EXTERNAL_NET`: Set the IP address range of external networks.
- `RULE_PATHS`: Specify the directory where the rules are located.
- `LOG_DIR`: Set the directory where the logs will be stored.
- `ENABLE_FILE_INSPECTION`: Enable file inspection.
- `ENABLE_TLS`: Enable TLS inspection.

Make sure to save the changes after modifying the configuration file.

### Starting and Stopping Suricata

To start Suricata, use the following command: `sudo suricata -c /etc/suricata/suricata.yaml -i <interface>`

To stop Suricata, press `Ctrl + C` in the terminal where it is running.

### Suricata Logs

Suricata generates logs that can be useful for analyzing network traffic. The logs are stored in the directory specified by the `LOG_DIR` configuration option.

The main log file is `eve.json`, which contains detailed information about network events. Other log files include `stats.log` for statistical information and `fast.log` for fast pattern matching alerts.

### Suricata Rules

Suricata uses rules to detect and alert on network events. The rules are stored in the directory specified by the `RULE_PATHS` configuration option.

You can create custom rules or use existing ones from the Suricata rule set. The rule files have the extension `.rules` and are written in the Suricata rule language.

### Suricata Alerts

When Suricata detects a network event that matches a rule, it generates an alert. The alerts are stored in the `eve.json` log file.

You can configure Suricata to send alerts to a SIEM system or an email address for further analysis.

### Suricata IPS Mode

Suricata can also be used as an Intrusion Prevention System (IPS). In IPS mode, Suricata can block network traffic that matches certain rules.

To enable IPS mode, set the `mode` option in the Suricata configuration file to `idsips`.

### Suricata and iptables

You can use Suricata in conjunction with iptables to enhance network security. iptables is a firewall utility that allows you to filter and manipulate network traffic.

By combining Suricata and iptables, you can create a powerful network security solution. Suricata can detect malicious traffic and iptables can block or redirect it.

To redirect traffic to Suricata, use the following iptables rule: `sudo iptables -A PREROUTING -j NFQUEUE --queue-num <queue_number>`

To block traffic using Suricata, use the following iptables rule: `sudo iptables -A OUTPUT -j NFQUEUE --queue-num <queue_number>`

Replace `<queue_number>` with the desired queue number.

Remember to save the iptables rules to persist across reboots.

### Conclusion

Suricata is a powerful network intrusion detection and prevention system. By properly installing, configuring, and using Suricata in conjunction with iptables, you can enhance the security of your network and detect potential threats.
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
### 规则定义

规则/签名由以下部分组成：

* **动作**，确定当规则匹配时会发生什么。
* **头部**，定义规则的协议、IP地址、端口和方向。
* **规则选项**，定义规则的具体内容。

![](<../../../.gitbook/assets/image (642) (3).png>)

#### **有效的动作包括**

* alert - 生成警报
* pass - 停止对数据包的进一步检查
* **drop** - 丢弃数据包并生成警报
* **reject** - 向匹配数据包的发送方发送RST/ICMP不可达错误。
* rejectsrc - 与 _reject_ 相同
* rejectdst - 向匹配数据包的接收方发送RST/ICMP错误数据包。
* rejectboth - 向对话的双方都发送RST/ICMP错误数据包。

#### **协议**

* tcp（用于tcp流量）
* udp
* icmp
* ip（ip代表“所有”或“任意”）
* _第7层协议_：http、ftp、tls、smb、dns、ssh...（更多详细信息请参阅[**文档**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html)）

#### 源地址和目标地址

它支持IP范围、否定和地址列表：

| 示例                          | 含义                                      |
| ---------------------------- | ---------------------------------------- |
| ! 1.1.1.1                    | 除了1.1.1.1之外的所有IP地址               |
| !\[1.1.1.1, 1.1.1.2]         | 除了1.1.1.1和1.1.1.2之外的所有IP地址      |
| $HOME\_NET                   | 在yaml中设置的HOME\_NET值                 |
| \[$EXTERNAL\_NET, !$HOME\_NET] | EXTERNAL\_NET而且不是HOME\_NET            |
| \[10.0.0.0/24, !10.0.0.5]    | 除了10.0.0.5之外的10.0.0.0/24              |

#### 源端口和目标端口

它支持端口范围、否定和端口列表

| 示例           | 含义                                      |
| -------------- | ---------------------------------------- |
| any            | 任何地址                                  |
| \[80, 81, 82]  | 端口80、81和82                            |
| \[80: 82]      | 从80到82的范围                            |
| \[1024: ]      | 从1024到最高端口号                        |
| !80            | 除了端口80之外的所有端口                   |
| \[80:100,!99]  | 从80到100的范围，但不包括99                |
| \[1:80,!\[2,4]] | 从1到80的范围，但不包括端口2和4            |

#### 方向

可以指示应用通信规则的方向：
```
source -> destination
source <> destination  (both directions)
```
#### 关键词

Suricata有**数百个选项**可用于搜索您正在寻找的**特定数据包**，如果找到有趣的内容，将在此处提及。请查阅[**文档**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/index.html)获取更多信息！
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

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者你想要**获取PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或者 [**Telegram群组**](https://t.me/peass) 或者 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>
