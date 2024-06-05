# Pcap 检查

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS 红队专家）</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想看到您的**公司在 HackTricks 中做广告**或**下载 PDF 版本的 HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 探索[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFT**](https://opensea.io/collection/the-peass-family)收藏
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** 上关注**我们。
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) 是西班牙最重要的网络安全活动之一，也是欧洲最重要的活动之一。作为促进技术知识的使命，这个大会是技术和网络安全专业人士在各个领域的热点交流地。

{% embed url="https://www.rootedcon.com/" %}

{% hint style="info" %}
关于 **PCAP** 和 **PCAPNG** 的说明：PCAP 文件格式有两个版本；**PCAPNG 是较新的版本，不是所有工具都支持**。您可能需要使用 Wireshark 或其他兼容工具将文件从 PCAPNG 转换为 PCAP，以便在其他一些工具中使用。
{% endhint %}

## 用于 pcap 的在线工具

* 如果您的 pcap 文件头部**损坏**，您应该尝试使用以下链接进行**修复**：[http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php)
* 在 [**PacketTotal**](https://packettotal.com) 中提取**信息**并搜索 pcap 中的**恶意软件**
* 使用 [**www.virustotal.com**](https://www.virustotal.com) 和 [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com) 搜索**恶意活动**
* 在 [**https://apackets.com/**](https://apackets.com/) 中通过浏览器进行**完整 pcap 分析**

## 提取信息

以下工具可用于提取统计数据、文件等。

### Wireshark

{% hint style="info" %}
**如果您要分析 PCAP，基本上必须了解如何使用 Wireshark**
{% endhint %}

您可以在以下链接找到一些 Wireshark 技巧：

{% content-ref url="wireshark-tricks.md" %}
[wireshark-tricks.md](wireshark-tricks.md)
{% endcontent-ref %}

### [**https://apackets.com/**](https://apackets.com/)

通过浏览器进行 pcap 分析。

### Xplico 框架

[**Xplico** ](https://github.com/xplico/xplico)（仅限 Linux）可以**分析** pcap 并从中提取信息。例如，Xplico 可从 pcap 文件中提取每封电子邮件（POP、IMAP 和 SMTP 协议）、所有 HTTP 内容、每个 VoIP 通话（SIP）、FTP、TFTP 等。

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
访问 _**127.0.0.1:9876**_，使用凭据 _**xplico:xplico**_

然后创建一个**新案例**，在案例内创建一个**新会话**，并**上传pcap文件**。

### NetworkMiner

像Xplico一样，这是一个用于**分析和提取pcap文件中对象的工具**。它有一个免费版本，您可以[**在这里下载**](https://www.netresec.com/?page=NetworkMiner)。它适用于**Windows**。\
这个工具还可以用来从数据包中**分析其他信息**，以便更快地了解发生了什么。

### NetWitness Investigator

您可以从[**这里下载NetWitness Investigator**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(它适用于Windows)**。\
这是另一个有用的工具，可以**分析数据包**并以有用的方式对信息进行分类，以**了解内部发生的情况**。

### [BruteShark](https://github.com/odedshimon/BruteShark)

* 提取和编码用户名和密码（HTTP、FTP、Telnet、IMAP、SMTP...）
* 提取认证哈希并使用Hashcat破解它们（Kerberos、NTLM、CRAM-MD5、HTTP-Digest...）
* 构建可视化网络图（网络节点和用户）
* 提取DNS查询
* 重建所有TCP和UDP会话
* 文件切割

### Capinfos
```
capinfos capture.pcap
```
### Ngrep

如果你想在 pcap 文件中查找某些内容，可以使用 ngrep。以下是一个使用主要过滤器的示例：
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### 数据恢复

使用常见的数据恢复技术可以帮助从 pcap 中提取文件和信息：

{% content-ref url="../partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### 捕获凭据

您可以使用类似 [https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz) 的工具来解析 pcap 或实时接口中的凭据。

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) 是**西班牙**最相关的网络安全活动之一，也是**欧洲**最重要的活动之一。作为促进技术知识的使命，这个大会是技术和网络安全专业人士在各个领域的热点交流平台。

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
**检查 pcap**
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[YaraPCAP](https://github.com/kevthehermit/YaraPcap) 是一个工具，可以：

- 读取 PCAP 文件并提取 Http 流。
- 解压缩任何压缩流
- 使用 yara 扫描每个文件
- 写入 report.txt
- 可选择将匹配的文件保存到一个目录

### 恶意软件分析

检查是否能找到任何已知恶意软件的指纹：

{% content-ref url="../malware-analysis.md" %}
[malware-analysis.md](../malware-analysis.md)
{% endcontent-ref %}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) 是一个被动的、开源的网络流量分析器。许多运营商使用 Zeek 作为网络安全监控器（NSM）来支持对可疑或恶意活动的调查。Zeek 还支持一系列超出安全领域的流量分析任务，包括性能测量和故障排除。

基本上，由 `zeek` 创建的日志不是 **pcaps**。因此，您将需要使用 **其他工具** 来分析包含有关 pcaps 的信息的日志。
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
## 其他 pcap 分析技巧

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

[**RootedCON**](https://www.rootedcon.com/) 是**西班牙**最重要的网络安全活动之一，也是**欧洲**最重要的之一。以**促进技术知识**为使命，这个大会是技术和网络安全专业人士在各个领域的热点会议。

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想看到您的**公司在 HackTricks 中做广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 探索[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFT**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** 上关注我们**。
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>
