# Pcap检查

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) 是西班牙最重要的网络安全活动之一，也是欧洲最重要的网络安全活动之一。作为促进技术知识的使命，这个大会是技术和网络安全专业人士在各个领域的热点交流。

{% embed url="https://www.rootedcon.com/" %}

{% hint style="info" %}
关于**PCAP**与**PCAPNG**的说明：PCAP文件格式有两个版本；**PCAPNG是较新的版本，不被所有工具支持**。您可能需要使用Wireshark或其他兼容工具将文件从PCAPNG转换为PCAP，以便在其他工具中使用它。
{% endhint %}

## 在线工具用于pcap

* 如果您的pcap文件头部**损坏**，您可以尝试使用：[http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php)
* 在[**PacketTotal**](https://packettotal.com)中提取**信息**并搜索pcap中的**恶意软件**
* 使用[**www.virustotal.com**](https://www.virustotal.com)和[**www.hybrid-analysis.com**](https://www.hybrid-analysis.com)搜索**恶意活动**

## 提取信息

以下工具对于提取统计信息、文件等非常有用。

### Wireshark

{% hint style="info" %}
**如果您要分析PCAP，您基本上必须知道如何使用Wireshark**
{% endhint %}

您可以在以下位置找到一些Wireshark技巧：

{% content-ref url="wireshark-tricks.md" %}
[wireshark-tricks.md](wireshark-tricks.md)
{% endcontent-ref %}

### Xplico Framework

[**Xplico** ](https://github.com/xplico/xplico)_(仅适用于Linux)_可以**分析**pcap并从中提取信息。例如，从pcap文件中，Xplico可以提取每个电子邮件（POP、IMAP和SMTP协议），所有HTTP内容，每个VoIP呼叫（SIP），FTP，TFTP等等。

**安装**
```bash
sudo bash -c 'echo "deb http://repo.xplico.org/ $(lsb_release -s -c) main" /etc/apt/sources.list'
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 791C25CE
sudo apt-get update
sudo apt-get install xplico
```
**运行**
```
/etc/init.d/apache2 restart
/etc/init.d/xplico start
```
访问使用凭据 _**xplico:xplico**_ 的 _**127.0.0.1:9876**_。

然后创建一个**新案例**，在案例中创建一个**新会话**，并**上传pcap文件**。

### NetworkMiner

与Xplico一样，这是一个用于**分析和提取pcap文件中的对象**的工具。你可以在[**这里**](https://www.netresec.com/?page=NetworkMiner)下载它的免费版本。它适用于**Windows**操作系统。\
这个工具还可以用来从数据包中获取**其他分析信息**，以便更快地了解发生了什么。

### NetWitness Investigator

你可以从[**这里**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware)下载NetWitness Investigator（它适用于Windows操作系统）。\
这是另一个有用的工具，它可以**分析数据包**并以有用的方式对信息进行排序，以便**了解内部发生的情况**。

![](<../../../.gitbook/assets/image (567) (1).png>)

### [BruteShark](https://github.com/odedshimon/BruteShark)

* 提取和编码用户名和密码（HTTP、FTP、Telnet、IMAP、SMTP...）
* 提取认证哈希并使用Hashcat破解（Kerberos、NTLM、CRAM-MD5、HTTP-Digest...）
* 构建可视化网络图（网络节点和用户）
* 提取DNS查询
* 重构所有TCP和UDP会话
* 文件切割

### Capinfos
```
capinfos capture.pcap
```
### Ngrep

如果你想在pcap文件中查找某些内容，可以使用ngrep。以下是使用主要过滤器的示例：
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### 数据恢复

使用常见的数据恢复技术可以从pcap中提取文件和信息：

{% content-ref url="../partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### 捕获凭证

您可以使用工具如[https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz)从pcap或实时接口中解析凭证。

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) 是西班牙最重要的网络安全活动之一，也是欧洲最重要的网络安全活动之一。作为促进技术知识的使命，这个大会是技术和网络安全专业人士在各个领域的热点交流平台。

{% embed url="https://www.rootedcon.com/" %}

## 检查漏洞/恶意软件

### Suricata

**安装和设置**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**检查 pcap 文件**

To analyze a pcap file, you can use tools like Wireshark or tcpdump. These tools allow you to inspect the network traffic captured in the pcap file.

要分析 pcap 文件，可以使用 Wireshark 或 tcpdump 等工具。这些工具允许您检查在 pcap 文件中捕获的网络流量。

**Inspect packets**

**检查数据包**

Once you have opened the pcap file in a packet analysis tool, you can start inspecting the individual packets. Look for any suspicious or abnormal behavior in the network traffic.

在数据包分析工具中打开 pcap 文件后，您可以开始检查各个数据包。查找网络流量中的任何可疑或异常行为。

**Filter packets**

**过滤数据包**

To focus on specific packets of interest, you can apply filters to the pcap file. Filters allow you to narrow down the packets based on specific criteria such as source or destination IP address, port number, protocol, or packet content.

为了关注感兴趣的特定数据包，可以对 pcap 文件应用过滤器。过滤器允许您根据特定的条件（如源或目标 IP 地址、端口号、协议或数据包内容）缩小数据包范围。

**Reconstruct sessions**

**重建会话**

In some cases, it may be necessary to reconstruct the sessions from the captured packets. This can be done by analyzing the packet headers and payload to identify the start and end of each session.

在某些情况下，可能需要从捕获的数据包中重建会话。这可以通过分析数据包头部和有效载荷来识别每个会话的开始和结束来完成。

**Extract files**

**提取文件**

If the pcap file contains file transfers or downloads, you can extract those files for further analysis. Look for packets with file attachments or HTTP requests/responses that include file content.

如果 pcap 文件包含文件传输或下载，可以提取这些文件进行进一步分析。查找带有文件附件或包含文件内容的 HTTP 请求/响应的数据包。

**Analyze timestamps**

**分析时间戳**

Timestamps in the pcap file can provide valuable information about the timing and sequence of network events. Analyzing the timestamps can help in understanding the order of network activities and identifying any time gaps or delays.

pcap 文件中的时间戳可以提供有关网络事件的时间和顺序的有价值的信息。分析时间戳可以帮助理解网络活动的顺序，并识别任何时间间隔或延迟。

**Follow TCP streams**

**跟踪 TCP 流**

To get a complete view of a TCP session, you can follow the TCP streams in the pcap file. This allows you to see the entire conversation between the client and server, including request and response payloads.

为了完整地查看 TCP 会话，可以在 pcap 文件中跟踪 TCP 流。这样可以看到客户端和服务器之间的完整对话，包括请求和响应的有效载荷。

**Identify anomalies**

**识别异常**

During the pcap inspection, keep an eye out for any anomalies or suspicious patterns in the network traffic. Look for unexpected protocols, unusual packet sizes, or any other indicators of potential security breaches.

在 pcap 检查过程中，注意网络流量中的任何异常或可疑模式。寻找意外的协议、异常的数据包大小或任何其他潜在安全漏洞的指示器。

**Document findings**

**记录发现**

As you analyze the pcap file, make sure to document your findings. Take notes on any interesting packets, suspicious activities, or potential security issues. This documentation will be useful for further investigation or reporting.

在分析 pcap 文件时，请确保记录您的发现。记录任何有趣的数据包、可疑活动或潜在的安全问题。这些记录将有助于进一步的调查或报告。
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) 是一个工具，它可以：

* 读取 PCAP 文件并提取 HTTP 流。
* 对任何压缩的流进行 gzip 解压缩。
* 使用 Yara 扫描每个文件。
* 写入 report.txt。
* 可选择将匹配的文件保存到一个目录。

### 恶意软件分析

检查是否能找到已知恶意软件的任何指纹：

{% content-ref url="../malware-analysis.md" %}
[malware-analysis.md](../malware-analysis.md)
{% endcontent-ref %}

## Zeek

> Zeek 是一个被动的、开源的网络流量分析器。许多运营商使用 Zeek 作为网络安全监视器 (NSM) 来支持对可疑或恶意活动的调查。Zeek 还支持广泛的流量分析任务，超出了安全领域，包括性能测量和故障排除。

基本上，由 `zeek` 创建的日志不是 **pcaps**。因此，您需要使用**其他工具**来分析包含有关 pcaps 的**信息**的日志。

### 连接信息
```bash
#Get info about longest connections (add "grep udp" to see only udp traffic)
#The longest connection might be of malware (constant reverse shell?)
cat conn.log | zeek-cut id.orig_h id.orig_p id.resp_h id.resp_p proto service duration | sort -nrk 7 | head -n 10

10.55.100.100   49778   65.52.108.225   443     tcp     -       86222.365445
10.55.100.107   56099   111.221.29.113  443     tcp     -       86220.126151
10.55.100.110   60168   40.77.229.82    443     tcp     -       86160.119664


#Improve the metrics by summing up the total duration time for connections that have the same destination IP and Port.
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto duration | awk 'BEGIN{ FS="\t" } { arr[$1 FS $2 FS $3 FS $4] += $5 } END{ for (key in arr) printf "%s%s%s\n", key, FS, arr[key] }' | sort -nrk 5 | head -n 10

10.55.100.100   65.52.108.225   443     tcp     86222.4
10.55.100.107   111.221.29.113  443     tcp     86220.1
10.55.100.110   40.77.229.82    443     tcp     86160.1

#Get the number of connections summed up per each line
cat conn.log | zeek-cut id.orig_h id.resp_h duration | awk 'BEGIN{ FS="\t" } { arr[$1 FS $2] += $3; count[$1 FS $2] += 1 } END{ for (key in arr) printf "%s%s%s%s%s\n", key, FS, count[key], FS, arr[key] }' | sort -nrk 4 | head -n 10

10.55.100.100   65.52.108.225   1       86222.4
10.55.100.107   111.221.29.113  1       86220.1
10.55.100.110   40.77.229.82    134       86160.1

#Check if any IP is connecting to 1.1.1.1
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto service | grep '1.1.1.1' | sort | uniq -c

#Get number of connections per source IP, dest IP and dest Port
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto | awk 'BEGIN{ FS="\t" } { arr[$1 FS $2 FS $3 FS $4] += 1 } END{ for (key in arr) printf "%s%s%s\n", key, FS, arr[key] }' | sort -nrk 5 | head -n 10


# RITA
#Something similar can be done with the tool rita
rita show-long-connections -H --limit 10 zeek_logs

+---------------+----------------+--------------------------+----------------+
|   SOURCE IP   | DESTINATION IP | DSTPORT:PROTOCOL:SERVICE |    DURATION    |
+---------------+----------------+--------------------------+----------------+
| 10.55.100.100 | 65.52.108.225  | 443:tcp:-                | 23h57m2.3655s  |
| 10.55.100.107 | 111.221.29.113 | 443:tcp:-                | 23h57m0.1262s  |
| 10.55.100.110 | 40.77.229.82   | 443:tcp:-                | 23h56m0.1197s  |

#Get connections info from rita
rita show-beacons zeek_logs | head -n 10
Score,Source IP,Destination IP,Connections,Avg Bytes,Intvl Range,Size Range,Top Intvl,Top Size,Top Intvl Count,Top Size Count,Intvl Skew,Size Skew,Intvl Dispersion,Size Dispersion
1,192.168.88.2,165.227.88.15,108858,197,860,182,1,89,53341,108319,0,0,0,0
1,10.55.100.111,165.227.216.194,20054,92,29,52,1,52,7774,20053,0,0,0,0
0.838,10.55.200.10,205.251.194.64,210,69,29398,4,300,70,109,205,0,0,0,0
```
### DNS 信息

DNS（域名系统）是一种用于将域名转换为 IP 地址的系统。在网络流量分析中，检查 DNS 信息可以提供有关通信的重要线索。以下是一些有用的 DNS 信息检查方法：

#### DNS 查询

通过检查 DNS 查询，可以了解主机正在尝试访问的域名。这可以帮助确定主机的意图和目标。

#### DNS 响应

检查 DNS 响应可以揭示主机是否成功解析了域名，并获取了相应的 IP 地址。这可以帮助确定主机是否与特定的服务器进行了通信。

#### DNS 转发

检查 DNS 转发可以显示主机是否将 DNS 查询发送到其他 DNS 服务器。这可以帮助确定主机是否使用了代理或中间人。

#### DNS 缓存

检查 DNS 缓存可以显示主机是否存储了先前的 DNS 查询结果。这可以帮助确定主机是否频繁访问相同的域名。

#### DNS 劫持

检查 DNS 劫持可以揭示主机是否受到了恶意攻击，其中攻击者篡改了 DNS 查询结果，将用户重定向到恶意网站。

#### DNS 异常

检查 DNS 异常可以显示主机是否存在异常的 DNS 查询或响应。这可以帮助确定主机是否受到了攻击或存在配置问题。

通过分析 DNS 信息，可以获得有关网络通信的重要线索，帮助进行取证分析和安全事件响应。
```bash
#Get info about each DNS request performed
cat dns.log | zeek-cut -c id.orig_h query qtype_name answers

#Get the number of times each domain was requested and get the top 10
cat dns.log | zeek-cut query | sort | uniq | rev | cut -d '.' -f 1-2 | rev | sort | uniq -c | sort -nr | head -n 10

#Get all the IPs
cat dns.log | zeek-cut id.orig_h query | grep 'example\.com' | cut -f 1 | sort | uniq -c

#Sort the most common DNS record request (should be A)
cat dns.log | zeek-cut qtype_name | sort | uniq -c | sort -nr

#See top DNS domain requested with rita
rita show-exploded-dns -H --limit 10 zeek_logs
```
## 其他pcap分析技巧

{% content-ref url="dnscat-exfiltration.md" %}
[dnscat-exfiltration.md](dnscat-exfiltration.md)
{% endcontent-ref %}

{% content-ref url="wifi-pcap-analysis.md" %}
[wifi-pcap-analysis.md](wifi-pcap-analysis.md)
{% endcontent-ref %}

{% content-ref url="usb-keystrokes.md" %}
[usb-keystrokes.md](usb-keystrokes.md)
{% endcontent-ref %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) 是西班牙最重要的网络安全活动之一，也是欧洲最重要的网络安全活动之一。作为促进技术知识的使命，这个大会是技术和网络安全专业人士的热点交流平台。

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家网络安全公司工作吗？你想在HackTricks中看到你的公司广告吗？或者你想获得PEASS的最新版本或下载PDF版本的HackTricks吗？请查看[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
