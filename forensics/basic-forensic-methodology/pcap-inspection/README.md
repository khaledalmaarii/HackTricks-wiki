# Інспекція Pcap

{% hint style="success" %}
Вивчайте та практикуйте хакінг AWS: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Навчання HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте хакінг GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Навчання HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримайте HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Поширюйте хакерські трюки, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв GitHub.

</details>
{% endhint %}

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) є найбільш важливою подією з кібербезпеки в **Іспанії** та однією з найважливіших в **Європі**. З місією просування технічних знань, цей конгрес є кипучою точкою зустрічі для професіоналів технологій та кібербезпеки у будь-якій галузі.

{% embed url="https://www.rootedcon.com/" %}

{% hint style="info" %}
Про **PCAP** проти **PCAPNG**: існують дві версії формату файлу PCAP; **PCAPNG є новішою і не підтримується всіма інструментами**. Можливо, вам доведеться конвертувати файл з PCAPNG в PCAP за допомогою Wireshark або іншого сумісного інструмента, щоб працювати з ним у деяких інших інструментах.
{% endhint %}

## Онлайн інструменти для pcap

* Якщо заголовок вашого pcap **пошкоджений**, вам слід спробувати **виправити** його за допомогою: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php)
* Витягніть **інформацію** та шукайте **шкідливе ПЗ** всередині pcap на [**PacketTotal**](https://packettotal.com)
* Шукайте **зловмисну діяльність** за допомогою [**www.virustotal.com**](https://www.virustotal.com) та [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com)

## Витягнення інформації

Наступні інструменти корисні для витягнення статистики, файлів і т. д.

### Wireshark

{% hint style="info" %}
**Якщо ви збираєтеся аналізувати PCAP, вам в основному слід знати, як використовувати Wireshark**
{% endhint %}

Деякі хитрощі Wireshark можна знайти в:

{% content-ref url="wireshark-tricks.md" %}
[wireshark-tricks.md](wireshark-tricks.md)
{% endcontent-ref %}

### Фреймворк Xplico

[**Xplico** ](https://github.com/xplico/xplico)_(тільки для Linux)_ може **аналізувати** pcap та витягувати з нього інформацію. Наприклад, з файлу pcap Xplico витягує кожен електронний лист (протоколи POP, IMAP та SMTP), всі вміст HTTP, кожний дзвінок VoIP (SIP), FTP, TFTP та інше.

**Встановлення**
```bash
sudo bash -c 'echo "deb http://repo.xplico.org/ $(lsb_release -s -c) main" /etc/apt/sources.list'
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 791C25CE
sudo apt-get update
sudo apt-get install xplico
```
**Виконання**
```
/etc/init.d/apache2 restart
/etc/init.d/xplico start
```
Открийте доступ до _**127.0.0.1:9876**_ з обліковими даними _**xplico:xplico**_

Потім створіть **новий кейс**, створіть **нову сесію** всередині кейсу та **завантажте файл pcap**.

### NetworkMiner

Подібно до Xplico, це інструмент для **аналізу та вилучення об'єктів з pcap**. Є безкоштовне видання, яке можна **завантажити** [**тут**](https://www.netresec.com/?page=NetworkMiner). Працює з **Windows**.\
Цей інструмент також корисний для отримання **іншої інформації, проаналізованої** з пакетів, щоб знати, що відбувалося **швидшим** способом.

### NetWitness Investigator

Ви можете завантажити [**NetWitness Investigator тут**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(Працює в Windows)**.\
Це ще один корисний інструмент, який **аналізує пакети** та сортує інформацію у корисний спосіб, щоб **знати, що відбувається всередині**.

### [BruteShark](https://github.com/odedshimon/BruteShark)

* Вилучення та кодування імен користувачів та паролів (HTTP, FTP, Telnet, IMAP, SMTP...)
* Вилучення хешів аутентифікації та їх розкриття за допомогою Hashcat (Kerberos, NTLM, CRAM-MD5, HTTP-Digest...)
* Побудова візуальної діаграми мережі (Мережеві вузли та користувачі)
* Вилучення запитів DNS
* Відновлення всіх TCP та UDP сесій
* Видобування файлів

### Capinfos
```
capinfos capture.pcap
```
### Ngrep

Якщо ви **шукаєте** щось усередині pcap, ви можете використовувати **ngrep**. Ось приклад використання основних фільтрів:
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Видалення

Використання загальних технік видалення може бути корисним для вилучення файлів та інформації з pcap:

{% content-ref url="../partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Захоплення облікових даних

Ви можете використовувати інструменти, такі як [https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz), щоб розбирати облікові дані з pcap або живого інтерфейсу.

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) - найбільш важлива подія з кібербезпеки в **Іспанії** та одна з найважливіших в **Європі**. З метою просування технічних знань, цей конгрес є кипучою точкою зустрічі для професіоналів технологій та кібербезпеки у будь-якій галузі.

{% embed url="https://www.rootedcon.com/" %}

## Перевірка Вразливостей/Шкідливих програм

### Suricata

**Встановлення та налаштування**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**Перевірка pcap**
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) - це інструмент, який

* Читає файл PCAP та витягує потоки Http.
* gzip розпаковує будь-які стиснуті потоки
* Сканує кожен файл за допомогою yara
* Записує звіт у report.txt
* Опціонально зберігає відповідні файли у каталозі

### Аналіз шкідливих програм

Перевірте, чи можете ви знайти будь-який відбиток відомої шкідливої програми:

{% content-ref url="../malware-analysis.md" %}
[malware-analysis.md](../malware-analysis.md)
{% endcontent-ref %}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) - це пасивний, відкритий аналізатор мережевого трафіку з відкритим вихідним кодом. Багато операторів використовують Zeek як монітор мережевої безпеки (NSM), щоб підтримувати розслідування підозрілої або зловмисної діяльності. Zeek також підтримує широкий спектр завдань аналізу трафіку поза областю безпеки, включаючи вимірювання продуктивності та усунення неполадок.

Фактично, журнали, створені `zeek`, не є **pcaps**. Тому вам потрібно використовувати **інші інструменти** для аналізу журналів, де є **інформація** про pcaps.
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
### Інформація DNS
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
## Інші хитрощі аналізу pcap

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

[**RootedCON**](https://www.rootedcon.com/) - найбільш важлива подія з кібербезпеки в **Іспанії** та одна з найважливіших в **Європі**. З **місією просування технічних знань** цей конгрес є кипучою точкою зустрічі для професіоналів технологій та кібербезпеки у будь-якій галузі.

{% embed url="https://www.rootedcon.com/" %}

{% hint style="success" %}
Вивчайте та практикуйте взлом AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Навчання HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте взлом GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Навчання HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримайте HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Поширюйте хакерські трюки, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на GitHub.

</details>
{% endhint %}
