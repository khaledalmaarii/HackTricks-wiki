# Suricata & Iptables 备忘单

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS 红队专家）</strong></a><strong>！</strong></summary>

* 您在**网络安全公司**工作吗？ 想要在 HackTricks 中看到您的**公司广告**？ 或者想要访问**PEASS 的最新版本或下载 HackTricks 的 PDF**？ 请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 探索[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFT 收藏品](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在 **Twitter** 上关注我 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向 [hacktricks 仓库](https://github.com/carlospolop/hacktricks) 和 [hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud) 提交 PR 来分享您的黑客技巧**。

</details>

## Iptables

### 链

在 iptables 中，规则列表被称为链，按顺序处理。其中，有三个主要链是普遍存在的，还有像 NAT 这样的其他链可能会根据系统的能力而得到支持。

- **Input 链**：用于管理传入连接的行为。
- **Forward 链**：用于处理不是发送到本地系统的传入连接。这对于充当路由器的设备是典型的，其中接收到的数据应转发到另一个目的地。当系统涉及路由、NAT 或类似活动时，此链主要相关。
- **Output 链**：专用于调节传出连接。

这些链确保网络流量的有序处理，允许指定详细规则来管理数据进入、通过和离开系统的流动。
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

### 安装与配置
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

[来自文档：](https://github.com/OISF/suricata/blob/master/doc/userguide/rules/intro.rst) 一个规则/签名由以下部分组成：

* **动作**，确定规则匹配时会发生什么。
* **头部**，定义规则的协议、IP地址、端口和方向。
* **规则选项**，定义规则的具体内容。
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **有效操作包括**

* alert - 生成警报
* pass - 停止对数据包的进一步检查
* **drop** - 丢弃数据包并生成警报
* **reject** - 向匹配数据包的发送方发送RST/ICMP不可达错误。
* rejectsrc - 与 _reject_ 相同
* rejectdst - 向匹配数据包的接收方发送RST/ICMP错误数据包。
* rejectboth - 向对话的双方发送RST/ICMP错误数据包。

#### **协议**

* tcp（用于tcp流量）
* udp
* icmp
* ip（ip代表‘all’或‘any’）
* _layer7协议_: http, ftp, tls, smb, dns, ssh...（更多内容请参阅[**文档**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html)）

#### 源地址和目标地址

支持IP范围、否定和地址列表：

| 示例                          | 含义                                   |
| ------------------------------ | ---------------------------------------- |
| ! 1.1.1.1                      | 除了1.1.1.1之外的所有IP地址             |
| !\[1.1.1.1, 1.1.1.2]           | 除了1.1.1.1和1.1.1.2之外的所有IP地址    |
| $HOME\_NET                     | 您在yaml中设置的HOME\_NET               |
| \[$EXTERNAL\_NET, !$HOME\_NET] | EXTERNAL\_NET而不是HOME\_NET            |
| \[10.0.0.0/24, !10.0.0.5]      | 10.0.0.0/24，但不包括10.0.0.5           |

#### 源端口和目标端口

支持端口范围、否定和端口列表

| 示例         | 含义                                |
| --------------- | -------------------------------------- |
| any             | 任何地址                            |
| \[80, 81, 82]   | 端口80、81和82                     |
| \[80: 82]       | 从80到82的范围                  |
| \[1024: ]       | 从1024到最高端口号                  |
| !80             | 除了80之外的所有端口                      |
| \[80:100,!99]   | 从80到100的范围，但排除99 |
| \[1:80,!\[2,4]] | 从1到80的范围，但排除端口2和4  |

#### 方向

可以指示应用通信规则的方向：
```
source -> destination
source <> destination  (both directions)
```
#### 关键词

在Suricata中有**数百个选项**可用于搜索您正在寻找的**特定数据包**，如果发现有趣的内容，将在此处提及。查看[**文档**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/index.html)获取更多信息！
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

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

* 您在**网络安全公司**工作吗？想要看到您的**公司在HackTricks中宣传**吗？或者想要访问**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS & HackTricks周边**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享您的黑客技巧**。

</details>
