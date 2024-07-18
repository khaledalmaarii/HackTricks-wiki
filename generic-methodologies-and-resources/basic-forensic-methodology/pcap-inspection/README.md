# Pcap Inspection

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) є найважливішою подією в сфері кібербезпеки в **Іспанії** та однією з найважливіших в **Європі**. З **метою просування технічних знань**, цей конгрес є гарячою точкою зустрічі для професіоналів у сфері технологій та кібербезпеки в усіх дисциплінах.

{% embed url="https://www.rootedcon.com/" %}

{% hint style="info" %}
Примітка про **PCAP** та **PCAPNG**: існує дві версії формату файлів PCAP; **PCAPNG є новішим і не підтримується всіма інструментами**. Вам може знадобитися конвертувати файл з PCAPNG в PCAP за допомогою Wireshark або іншого сумісного інструменту, щоб працювати з ним в деяких інших інструментах.
{% endhint %}

## Online tools for pcaps

* Якщо заголовок вашого pcap **пошкоджений**, ви повинні спробувати **виправити** його за допомогою: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php)
* Витягніть **інформацію** та шукайте **шкідливе ПЗ** всередині pcap в [**PacketTotal**](https://packettotal.com)
* Шукайте **шкідливу активність** за допомогою [**www.virustotal.com**](https://www.virustotal.com) та [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com)
* **Повний аналіз pcap з браузера в** [**https://apackets.com/**](https://apackets.com/)

## Extract Information

Наступні інструменти корисні для витягування статистики, файлів тощо.

### Wireshark

{% hint style="info" %}
**Якщо ви збираєтеся аналізувати PCAP, ви в основному повинні знати, як користуватися Wireshark**
{% endhint %}

Ви можете знайти деякі трюки Wireshark у:

{% content-ref url="wireshark-tricks.md" %}
[wireshark-tricks.md](wireshark-tricks.md)
{% endcontent-ref %}

### [**https://apackets.com/**](https://apackets.com/)

Аналіз pcap з браузера.

### Xplico Framework

[**Xplico** ](https://github.com/xplico/xplico)_(тільки linux)_ може **аналізувати** **pcap** та витягувати інформацію з нього. Наприклад, з файлу pcap Xplico витягує кожен електронний лист (POP, IMAP та SMTP протоколи), весь HTTP контент, кожен VoIP дзвінок (SIP), FTP, TFTP тощо.

**Встановіть**
```bash
sudo bash -c 'echo "deb http://repo.xplico.org/ $(lsb_release -s -c) main" /etc/apt/sources.list'
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 791C25CE
sudo apt-get update
sudo apt-get install xplico
```
**Запустити**
```
/etc/init.d/apache2 restart
/etc/init.d/xplico start
```
Доступ до _**127.0.0.1:9876**_ з обліковими даними _**xplico:xplico**_

Потім створіть **нову справу**, створіть **нову сесію** всередині справи та **завантажте pcap** файл.

### NetworkMiner

Як і Xplico, це інструмент для **аналізу та вилучення об'єктів з pcaps**. Він має безкоштовну версію, яку ви можете **завантажити** [**тут**](https://www.netresec.com/?page=NetworkMiner). Він працює на **Windows**.\
Цей інструмент також корисний для отримання **іншої інформації, проаналізованої** з пакетів, щоб мати можливість швидше зрозуміти, що відбувалося.

### NetWitness Investigator

Ви можете завантажити [**NetWitness Investigator звідси**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(Працює на Windows)**.\
Це ще один корисний інструмент, який **аналізує пакети** та сортує інформацію у зручний спосіб, щоб **знати, що відбувається всередині**.

### [BruteShark](https://github.com/odedshimon/BruteShark)

* Вилучення та кодування імен користувачів і паролів (HTTP, FTP, Telnet, IMAP, SMTP...)
* Вилучення хешів аутентифікації та їх зламування за допомогою Hashcat (Kerberos, NTLM, CRAM-MD5, HTTP-Digest...)
* Створення візуальної мережевої діаграми (мережеві вузли та користувачі)
* Вилучення DNS запитів
* Відновлення всіх TCP та UDP сесій
* Вилучення файлів

### Capinfos
```
capinfos capture.pcap
```
### Ngrep

Якщо ви **шукаєте** **щось** всередині pcap, ви можете використовувати **ngrep**. Ось приклад з використанням основних фільтрів:
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Carving

Використання загальних технік карвінгу може бути корисним для витягування файлів та інформації з pcap:

{% content-ref url="../partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Capturing credentials

Ви можете використовувати інструменти, такі як [https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz), для парсингу облікових даних з pcap або живого інтерфейсу.

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) є найважливішою подією в сфері кібербезпеки в **Іспанії** та однією з найважливіших в **Європі**. З **метою просування технічних знань**, цей конгрес є гарячою точкою зустрічі для професіоналів у сфері технологій та кібербезпеки в усіх дисциплінах.

{% embed url="https://www.rootedcon.com/" %}

## Check Exploits/Malware

### Suricata

**Встановлення та налаштування**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**Перевірте pcap**
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) - це інструмент, який

* Читає файл PCAP та витягує HTTP потоки.
* Розпаковує будь-які стиснуті потоки за допомогою gzip.
* Сканує кожен файл за допомогою yara.
* Пише report.txt.
* За бажанням зберігає відповідні файли в директорію.

### Malware Analysis

Перевірте, чи можете ви знайти будь-які відбитки відомого шкідливого ПЗ:

{% content-ref url="../malware-analysis.md" %}
[malware-analysis.md](../malware-analysis.md)
{% endcontent-ref %}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) - це пасивний, відкритий аналізатор мережевого трафіку. Багато операторів використовують Zeek як монітор безпеки мережі (NSM) для підтримки розслідувань підозрілої або шкідливої діяльності. Zeek також підтримує широкий спектр завдань аналізу трафіку, які виходять за межі безпеки, включаючи вимірювання продуктивності та усунення неполадок.

В основному, журнали, створені `zeek`, не є **pcaps**. Тому вам потрібно буде використовувати **інші інструменти** для аналізу журналів, де міститься **інформація** про pcaps.

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
### DNS інформація
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
## Інші трюки аналізу pcap

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

[**RootedCON**](https://www.rootedcon.com/) є найактуальнішою подією в сфері кібербезпеки в **Іспанії** та однією з найважливіших в **Європі**. З **метою просування технічних знань**, цей конгрес є гарячою точкою зустрічі для професіоналів у сфері технологій та кібербезпеки в усіх дисциплінах.

{% embed url="https://www.rootedcon.com/" %}

{% hint style="success" %}
Вивчайте та практикуйте AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримати HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Діліться трюками хакінгу, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на github.

</details>
{% endhint %}
