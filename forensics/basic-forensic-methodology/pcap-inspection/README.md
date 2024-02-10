# Pcap 검사

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/)은 **스페인**에서 가장 관련성 높은 사이버 보안 행사이며 **유럽**에서 가장 중요한 행사 중 하나입니다. **기술적인 지식을 촉진**하기 위한 미션을 가진 이 회의는 모든 분야의 기술 및 사이버 보안 전문가들에게 열정적인 만남의 장입니다.

{% embed url="https://www.rootedcon.com/" %}

{% hint style="info" %}
**PCAP** 대 **PCAPNG**에 대한 참고 사항: PCAP 파일 형식에는 두 가지 버전이 있습니다. **PCAPNG은 더 최신이며 모든 도구에서 지원되지 않습니다**. 다른 도구에서 작업하기 위해 파일을 PCAPNG에서 PCAP으로 변환해야 할 수도 있습니다.
{% endhint %}

## PCAP을 위한 온라인 도구

* PCAP의 헤더가 **손상**된 경우 [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php)를 사용하여 **수정**을 시도해야 합니다.
* [**PacketTotal**](https://packettotal.com)에서 pcap 내에서 **정보**를 추출하고 **악성 코드**를 검색하세요.
* [**www.virustotal.com**](https://www.virustotal.com) 및 [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com)을 사용하여 **악성 활동**을 검색하세요.

## 정보 추출

다음 도구는 통계, 파일 등을 추출하는 데 유용합니다.

### Wireshark

{% hint style="info" %}
**PCAP를 분석할 예정이라면 Wireshark 사용 방법을 알아야 합니다.**
{% endhint %}

Wireshark의 몇 가지 트릭을 다음에서 찾을 수 있습니다:

{% content-ref url="wireshark-tricks.md" %}
[wireshark-tricks.md](wireshark-tricks.md)
{% endcontent-ref %}

### Xplico Framework

[**Xplico** ](https://github.com/xplico/xplico)_(only linux)_는 **pcap**을 분석하고 정보를 추출할 수 있습니다. 예를 들어, pcap 파일에서 Xplico는 각 이메일 (POP, IMAP 및 SMTP 프로토콜), 모든 HTTP 콘텐츠, 각 VoIP 통화 (SIP), FTP, TFTP 등을 추출합니다.

**설치**
```bash
sudo bash -c 'echo "deb http://repo.xplico.org/ $(lsb_release -s -c) main" /etc/apt/sources.list'
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 791C25CE
sudo apt-get update
sudo apt-get install xplico
```
**실행**
```
/etc/init.d/apache2 restart
/etc/init.d/xplico start
```
_**127.0.0.1:9876**_에 _**xplico:xplico**_ 자격 증명으로 액세스합니다.

그런 다음 **새로운 사례**를 만들고 사례 내에서 **새로운 세션**을 만들고 **pcap** 파일을 **업로드**합니다.

### NetworkMiner

Xplico와 마찬가지로 pcap에서 **객체를 분석하고 추출하는 도구**입니다. [**여기에서**](https://www.netresec.com/?page=NetworkMiner) 무료 버전을 **다운로드**할 수 있습니다. **Windows**와 호환됩니다.\
이 도구는 패킷에서 **다른 정보를 분석**하여 더 **빠르게** 무슨 일이 일어났는지 알 수 있도록 도움이 됩니다.

### NetWitness Investigator

[**여기에서 NetWitness Investigator를 다운로드**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware)할 수 있습니다. **(Windows에서 작동합니다)**.\
이는 패킷을 **분석**하고 정보를 유용한 방식으로 **정렬하여 내부에서 무슨 일이 일어나고 있는지 알 수 있는** 또 다른 유용한 도구입니다.

### [BruteShark](https://github.com/odedshimon/BruteShark)

* 사용자 이름과 암호 추출 및 인코딩 (HTTP, FTP, Telnet, IMAP, SMTP...)
* 인증 해시 추출 및 Hashcat을 사용하여 해독 (Kerberos, NTLM, CRAM-MD5, HTTP-Digest...)
* 시각적 네트워크 다이어그램 작성 (네트워크 노드 및 사용자)
* DNS 쿼리 추출
* 모든 TCP 및 UDP 세션 재구성
* 파일 조각 추출

### Capinfos
```
capinfos capture.pcap
```
### Ngrep

pcap 내에서 **무언가**를 **찾고** 있다면 **ngrep**을 사용할 수 있습니다. 다음은 주요 필터를 사용한 예시입니다:
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### 조각내기

일반적인 조각내기 기술을 사용하여 pcap에서 파일과 정보를 추출하는 데 유용할 수 있습니다:

{% content-ref url="../partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### 자격 증명 캡처

[https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz)와 같은 도구를 사용하여 pcap 또는 실시간 인터페이스에서 자격 증명을 구문 분석할 수 있습니다.

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/)은 **스페인**에서 가장 관련성 있는 사이버 보안 행사 중 하나로 **유럽**에서 가장 중요한 행사 중 하나입니다. **기술적인 지식을 촉진하는 미션**을 가지고 있는 이 회의는 모든 분야의 기술 및 사이버 보안 전문가들에게 열정적인 만남의 장입니다.

{% embed url="https://www.rootedcon.com/" %}

## Exploits/Malware 확인

### Suricata

**설치 및 설정**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**pcap 확인**

To analyze network traffic and investigate potential security incidents, it is often necessary to inspect pcap (Packet Capture) files. These files contain recorded network packets that can provide valuable information about network communications.

To check a pcap file, you can use various tools such as Wireshark, tcpdump, or tshark. These tools allow you to open the pcap file and view its contents, including the captured packets, their headers, and payload data.

By inspecting the pcap file, you can identify various network activities, such as HTTP requests, DNS queries, FTP transfers, or even suspicious traffic patterns. This information can help you understand the behavior of network devices, detect anomalies, and uncover potential security breaches.

When analyzing a pcap file, it is important to focus on specific aspects, such as source and destination IP addresses, port numbers, protocol types, and packet payloads. By examining these details, you can gain insights into the network traffic and identify any malicious or unauthorized activities.

In addition to manual inspection, you can also automate the analysis of pcap files using scripting languages like Python. This allows you to extract specific information from the pcap file, filter packets based on criteria, and perform more advanced analysis techniques.

Overall, checking pcap files is an essential step in the forensic investigation process. It helps uncover evidence, understand network behavior, and identify potential security threats.
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap)는 다음과 같은 기능을 수행하는 도구입니다.

* PCAP 파일을 읽고 HTTP 스트림을 추출합니다.
* 압축된 스트림을 gzip으로 해제합니다.
* 모든 파일을 Yara로 스캔합니다.
* report.txt를 작성합니다.
* 필요한 경우 일치하는 파일을 디렉토리에 저장합니다.

### 악성코드 분석

알려진 악성코드의 지문을 찾을 수 있는지 확인하세요:

{% content-ref url="../malware-analysis.md" %}
[malware-analysis.md](../malware-analysis.md)
{% endcontent-ref %}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html)는 수동적인 오픈 소스 네트워크 트래픽 분석기입니다. 많은 운영자들은 의심스러운 또는 악성 활동의 조사를 지원하기 위해 Zeek를 네트워크 보안 모니터(NSM)로 사용합니다. Zeek는 보안 도메인을 넘어서 성능 측정 및 문제 해결을 포함한 다양한 트래픽 분석 작업을 지원합니다.

기본적으로 `zeek`가 생성하는 로그는 **pcap**이 아닙니다. 따라서 **다른 도구**를 사용하여 pcap에 대한 정보를 분석해야 합니다.

### 연결 정보
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
### DNS 정보

DNS(Domain Name System)은 인터넷에서 도메인 이름을 IP 주소로 변환하는 시스템입니다. DNS 정보는 패킷 캡처 파일(pcap)을 검사하여 도메인 이름과 관련된 정보를 얻는 데 사용될 수 있습니다.

#### DNS 쿼리

DNS 쿼리는 도메인 이름을 IP 주소로 변환하기 위해 DNS 서버에 보내는 요청입니다. pcap 파일을 검사하여 DNS 쿼리를 확인할 수 있습니다. DNS 쿼리는 다음과 같은 형식을 가질 수 있습니다:

```
[Query Name] [Query Type] [Query Class]
```

- Query Name: 도메인 이름
- Query Type: DNS 레코드 유형 (예: A, AAAA, MX 등)
- Query Class: DNS 클래스 (일반적으로 IN)

#### DNS 응답

DNS 응답은 DNS 서버에서 도메인 이름에 대한 IP 주소 또는 기타 정보를 반환하는 것입니다. pcap 파일을 검사하여 DNS 응답을 확인할 수 있습니다. DNS 응답은 다음과 같은 형식을 가질 수 있습니다:

```
[Query Name] [Query Type] [Query Class] [TTL] [Answer Type] [Answer Data]
```

- Query Name: 도메인 이름
- Query Type: DNS 레코드 유형 (예: A, AAAA, MX 등)
- Query Class: DNS 클래스 (일반적으로 IN)
- TTL (Time to Live): DNS 레코드의 유효 기간
- Answer Type: 응답의 유형 (예: A, AAAA, MX 등)
- Answer Data: 응답 데이터 (예: IP 주소, 메일 서버 등)

#### DNS 레코드 유형

DNS 레코드 유형은 DNS 쿼리 및 응답에서 사용되는 다양한 유형의 정보를 나타냅니다. 일부 일반적인 DNS 레코드 유형은 다음과 같습니다:

- A: 도메인 이름에 대한 IPv4 주소
- AAAA: 도메인 이름에 대한 IPv6 주소
- MX: 도메인 이름에 대한 메일 서버
- NS: 도메인 이름에 대한 네임 서버
- CNAME: 도메인 이름에 대한 별칭
- TXT: 도메인 이름에 대한 텍스트 정보

#### DNS 정보 추출

pcap 파일을 검사하여 DNS 정보를 추출하는 방법은 다음과 같습니다:

1. pcap 파일을 Wireshark 또는 tcpdump와 같은 패킷 캡처 도구로 엽니다.
2. DNS 쿼리 및 응답 패킷을 필터링합니다.
3. 필터링된 패킷에서 DNS 쿼리 및 응답 정보를 확인합니다.
4. 도메인 이름, IP 주소, DNS 레코드 유형 등의 정보를 기록합니다.

DNS 정보 추출은 네트워크 트래픽 분석 및 보안 조사에 유용한 도구입니다.
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
## 다른 pcap 분석 트릭

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

[**RootedCON**](https://www.rootedcon.com/)은 **스페인**에서 가장 관련성 높은 사이버 보안 행사이며 **유럽**에서 가장 중요한 행사 중 하나입니다. **기술적인 지식을 촉진하는 미션**을 가지고 있는 이 회의는 모든 분야의 기술 및 사이버 보안 전문가들에게 열정적인 만남의 장입니다.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 **제로에서 영웅까지 AWS 해킹 배우기**!</summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family)인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**를** 팔로우하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 **자신의 해킹 트릭을 공유**하세요.

</details>
