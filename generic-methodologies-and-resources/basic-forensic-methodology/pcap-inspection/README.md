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

[**RootedCON**](https://www.rootedcon.com/) è l'evento di cybersecurity più rilevante in **Spagna** e uno dei più importanti in **Europa**. Con **la missione di promuovere la conoscenza tecnica**, questo congresso è un punto di incontro vivace per professionisti della tecnologia e della cybersecurity in ogni disciplina.

{% embed url="https://www.rootedcon.com/" %}

{% hint style="info" %}
Una nota su **PCAP** vs **PCAPNG**: ci sono due versioni del formato di file PCAP; **PCAPNG è più recente e non supportato da tutti gli strumenti**. Potresti dover convertire un file da PCAPNG a PCAP utilizzando Wireshark o un altro strumento compatibile, per poter lavorare con esso in alcuni altri strumenti.
{% endhint %}

## Online tools for pcaps

* Se l'intestazione del tuo pcap è **rotta** dovresti provare a **ripararla** usando: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php)
* Estrai **informazioni** e cerca **malware** all'interno di un pcap in [**PacketTotal**](https://packettotal.com)
* Cerca **attività malevole** usando [**www.virustotal.com**](https://www.virustotal.com) e [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com)
* **Analisi completa del pcap dal browser in** [**https://apackets.com/**](https://apackets.com/)

## Extract Information

I seguenti strumenti sono utili per estrarre statistiche, file, ecc.

### Wireshark

{% hint style="info" %}
**Se intendi analizzare un PCAP devi sostanzialmente sapere come usare Wireshark**
{% endhint %}

Puoi trovare alcuni trucchi di Wireshark in:

{% content-ref url="wireshark-tricks.md" %}
[wireshark-tricks.md](wireshark-tricks.md)
{% endcontent-ref %}

### [**https://apackets.com/**](https://apackets.com/)

Analisi del pcap dal browser.

### Xplico Framework

[**Xplico** ](https://github.com/xplico/xplico)_(solo linux)_ può **analizzare** un **pcap** ed estrarre informazioni da esso. Ad esempio, da un file pcap Xplico estrae ogni email (protocollo POP, IMAP e SMTP), tutti i contenuti HTTP, ogni chiamata VoIP (SIP), FTP, TFTP, e così via.

**Installa**
```bash
sudo bash -c 'echo "deb http://repo.xplico.org/ $(lsb_release -s -c) main" /etc/apt/sources.list'
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 791C25CE
sudo apt-get update
sudo apt-get install xplico
```
**Esegui**
```
/etc/init.d/apache2 restart
/etc/init.d/xplico start
```
Accesso a _**127.0.0.1:9876**_ con credenziali _**xplico:xplico**_

Poi crea un **nuovo caso**, crea una **nuova sessione** all'interno del caso e **carica il file pcap**.

### NetworkMiner

Come Xplico, è uno strumento per **analizzare ed estrarre oggetti dai pcap**. Ha un'edizione gratuita che puoi **scaricare** [**qui**](https://www.netresec.com/?page=NetworkMiner). Funziona con **Windows**.\
Questo strumento è anche utile per ottenere **ulteriori informazioni analizzate** dai pacchetti per poter sapere cosa stava succedendo in modo **più veloce**.

### NetWitness Investigator

Puoi scaricare [**NetWitness Investigator da qui**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(Funziona in Windows)**.\
Questo è un altro strumento utile che **analizza i pacchetti** e ordina le informazioni in un modo utile per **sapere cosa sta succedendo all'interno**.

### [BruteShark](https://github.com/odedshimon/BruteShark)

* Estrazione e codifica di nomi utente e password (HTTP, FTP, Telnet, IMAP, SMTP...)
* Estrazione degli hash di autenticazione e cracking utilizzando Hashcat (Kerberos, NTLM, CRAM-MD5, HTTP-Digest...)
* Creazione di un diagramma di rete visivo (Nodi di rete e utenti)
* Estrazione delle query DNS
* Ricostruzione di tutte le sessioni TCP e UDP
* File Carving

### Capinfos
```
capinfos capture.pcap
```
### Ngrep

Se stai **cercando** **qualcosa** all'interno del pcap puoi usare **ngrep**. Ecco un esempio che utilizza i filtri principali:
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Carving

Utilizzare tecniche di carving comuni può essere utile per estrarre file e informazioni dal pcap:

{% content-ref url="../partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Catturare credenziali

Puoi utilizzare strumenti come [https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz) per analizzare le credenziali da un pcap o da un'interfaccia live.

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) è l'evento di cybersecurity più rilevante in **Spagna** e uno dei più importanti in **Europa**. Con **la missione di promuovere la conoscenza tecnica**, questo congresso è un punto di incontro vivace per professionisti della tecnologia e della cybersecurity in ogni disciplina.

{% embed url="https://www.rootedcon.com/" %}

## Controlla Exploits/Malware

### Suricata

**Installa e configura**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**Controlla pcap**
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) è uno strumento che

* Legge un file PCAP ed estrae flussi Http.
* gzip decomprime eventuali flussi compressi
* Scansiona ogni file con yara
* Scrive un report.txt
* Facoltativamente salva i file corrispondenti in una directory

### Analisi Malware

Controlla se riesci a trovare qualche impronta di un malware noto:

{% content-ref url="../malware-analysis.md" %}
[malware-analysis.md](../malware-analysis.md)
{% endcontent-ref %}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) è un analizzatore di traffico di rete passivo e open-source. Molti operatori utilizzano Zeek come Monitor di Sicurezza di Rete (NSM) per supportare le indagini su attività sospette o malevole. Zeek supporta anche una vasta gamma di compiti di analisi del traffico oltre il dominio della sicurezza, inclusi la misurazione delle prestazioni e la risoluzione dei problemi.

Fondamentalmente, i log creati da `zeek` non sono **pcaps**. Pertanto, sarà necessario utilizzare **altri strumenti** per analizzare i log dove si trova l'**informazione** sui pcaps.

### Informazioni sulle Connessioni
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
### Informazioni DNS
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
## Altri trucchi per l'analisi pcap

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

[**RootedCON**](https://www.rootedcon.com/) è l'evento di cybersecurity più rilevante in **Spagna** e uno dei più importanti in **Europa**. Con **la missione di promuovere la conoscenza tecnica**, questo congresso è un punto di incontro vivace per professionisti della tecnologia e della cybersecurity in ogni disciplina.

{% embed url="https://www.rootedcon.com/" %}

{% hint style="success" %}
Impara e pratica AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos su github.

</details>
{% endhint %}
