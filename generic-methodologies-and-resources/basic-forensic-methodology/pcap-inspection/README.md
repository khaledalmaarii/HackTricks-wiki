# Pcap İncelemesi

{% hint style="success" %}
AWS Hacking öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **Bize katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya **bizi** **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) **İspanya'daki** en ilgili siber güvenlik etkinliği ve **Avrupa'daki** en önemli etkinliklerden biridir. **Teknik bilgiyi teşvik etme misyonu** ile bu kongre, her disiplindeki teknoloji ve siber güvenlik profesyonelleri için kaynayan bir buluşma noktasıdır.

{% embed url="https://www.rootedcon.com/" %}

{% hint style="info" %}
**PCAP** ile **PCAPNG** hakkında bir not: PCAP dosya formatının iki versiyonu vardır; **PCAPNG daha yenidir ve tüm araçlar tarafından desteklenmez**. Bazı diğer araçlarla çalışabilmek için bir dosyayı PCAPNG'den PCAP'a dönüştürmeniz gerekebilir, bunu Wireshark veya başka bir uyumlu araç kullanarak yapabilirsiniz.
{% endhint %}

## Pcap'ler için Çevrimiçi Araçlar

* Pcap'inizin başlığı **bozuksa**, bunu düzeltmek için şunu deneyin: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php)
* Bir pcap içindeki **bilgileri** çıkarın ve **kötü amaçlı yazılım** arayın [**PacketTotal**](https://packettotal.com) içinde
* **Kötü niyetli etkinlik** aramak için [**www.virustotal.com**](https://www.virustotal.com) ve [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com) kullanın
* **Tarayıcıdan tam pcap analizi için** [**https://apackets.com/**](https://apackets.com/)

## Bilgi Çıkarma

Aşağıdaki araçlar istatistik, dosya vb. çıkarmak için kullanışlıdır.

### Wireshark

{% hint style="info" %}
**Bir PCAP analiz edecekseniz, temelde Wireshark'ı nasıl kullanacağınızı bilmelisiniz**
{% endhint %}

Bazı Wireshark ipuçlarını burada bulabilirsiniz:

{% content-ref url="wireshark-tricks.md" %}
[wireshark-tricks.md](wireshark-tricks.md)
{% endcontent-ref %}

### [**https://apackets.com/**](https://apackets.com/)

Tarayıcıdan pcap analizi.

### Xplico Framework

[**Xplico** ](https://github.com/xplico/xplico)_(sadece linux)_ bir **pcap** analiz edebilir ve ondan bilgi çıkarabilir. Örneğin, bir pcap dosyasından Xplico, her e-postayı (POP, IMAP ve SMTP protokolleri), tüm HTTP içeriklerini, her VoIP çağrısını (SIP), FTP, TFTP vb. çıkarır.

**Kurulum**
```bash
sudo bash -c 'echo "deb http://repo.xplico.org/ $(lsb_release -s -c) main" /etc/apt/sources.list'
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 791C25CE
sudo apt-get update
sudo apt-get install xplico
```
**Çalıştır**
```
/etc/init.d/apache2 restart
/etc/init.d/xplico start
```
_**127.0.0.1:9876**_ adresine _**xplico:xplico**_ kimlik bilgileriyle erişin.

Ardından **yeni bir vaka** oluşturun, vaka içinde **yeni bir oturum** oluşturun ve **pcap** dosyasını **yükleyin**.

### NetworkMiner

Xplico gibi, **pcap'lerden nesneleri analiz etmek ve çıkarmak** için bir araçtır. **Buradan** [**indirebileceğiniz**](https://www.netresec.com/?page=NetworkMiner) ücretsiz bir sürümü vardır. **Windows** ile çalışır.\
Bu araç, paketlerden **diğer bilgilerin analiz edilmesi** için de faydalıdır, böylece ne olduğunu **daha hızlı** bir şekilde anlayabilirsiniz.

### NetWitness Investigator

[**NetWitness Investigator'ı buradan indirin**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(Windows'ta çalışır)**.\
Bu, paketleri **analiz eden** ve bilgileri **içeride ne olduğunu bilmek için** faydalı bir şekilde sıralayan başka bir kullanışlı araçtır.

### [BruteShark](https://github.com/odedshimon/BruteShark)

* Kullanıcı adlarını ve şifreleri çıkarmak ve kodlamak (HTTP, FTP, Telnet, IMAP, SMTP...)
* Kimlik doğrulama hash'lerini çıkarmak ve Hashcat kullanarak kırmak (Kerberos, NTLM, CRAM-MD5, HTTP-Digest...)
* Görsel bir ağ diyagramı oluşturmak (Ağ düğümleri ve kullanıcılar)
* DNS sorgularını çıkarmak
* Tüm TCP ve UDP oturumlarını yeniden oluşturmak
* Dosya Kesme

### Capinfos
```
capinfos capture.pcap
```
### Ngrep

Eğer pcap içinde **bir şey** **aramak** istiyorsanız **ngrep** kullanabilirsiniz. İşte ana filtreleri kullanan bir örnek:
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Carving

Yaygın carving tekniklerini kullanmak, pcap'tan dosyaları ve bilgileri çıkarmak için faydalı olabilir:

{% content-ref url="../partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Kimlik bilgilerini yakalama

Bir pcap veya canlı arayüzden kimlik bilgilerini ayrıştırmak için [https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz) gibi araçları kullanabilirsiniz.

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) **İspanya**'daki en ilgili siber güvenlik etkinliği ve **Avrupa**'daki en önemli etkinliklerden biridir. **Teknik bilgiyi teşvik etme misyonu** ile bu kongre, her disiplindeki teknoloji ve siber güvenlik profesyonelleri için kaynayan bir buluşma noktasıdır.

{% embed url="https://www.rootedcon.com/" %}

## Exploitler/Malware Kontrolü

### Suricata

**Kurulum ve ayar**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**pcap kontrol et**
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) bir araçtır

* Bir PCAP Dosyasını okur ve Http Akışlarını çıkarır.
* Herhangi bir sıkıştırılmış akışı gzip ile açar
* Her dosyayı yara ile tarar
* report.txt dosyası yazar
* İsteğe bağlı olarak eşleşen dosyaları bir Dizin'e kaydeder

### Malware Analysis

Bilinen bir kötü amaçlı yazılımın herhangi bir parmak izini bulup bulamayacağını kontrol edin:

{% content-ref url="../malware-analysis.md" %}
[malware-analysis.md](../malware-analysis.md)
{% endcontent-ref %}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) pasif, açık kaynaklı bir ağ trafiği analizörüdür. Birçok operatör, şüpheli veya kötü niyetli etkinliklerin araştırmalarını desteklemek için Zeek'i bir Ağ Güvenliği İzleyici (NSM) olarak kullanır. Zeek ayrıca güvenlik alanının ötesinde, performans ölçümü ve sorun giderme dahil olmak üzere geniş bir trafik analizi görev yelpazesini destekler.

Temelde, `zeek` tarafından oluşturulan günlükler **pcap** değildir. Bu nedenle, **pcaplar** hakkında **bilgilerin** bulunduğu günlükleri analiz etmek için **diğer araçlar** kullanmanız gerekecektir.

### Connections Info
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
### DNS bilgisi
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
## Diğer pcap analiz ipuçları

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

[**RootedCON**](https://www.rootedcon.com/) **İspanya**'daki en ilgili siber güvenlik etkinliği ve **Avrupa**'daki en önemli etkinliklerden biridir. **Teknik bilgiyi teşvik etme misyonu** ile bu kongre, her disiplinde teknoloji ve siber güvenlik profesyonelleri için kaynayan bir buluşma noktasıdır.

{% embed url="https://www.rootedcon.com/" %}

{% hint style="success" %}
AWS Hacking öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter**'da **bizi takip edin** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
