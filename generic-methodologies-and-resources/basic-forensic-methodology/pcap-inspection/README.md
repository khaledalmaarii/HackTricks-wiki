# Ispezione Pcap

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) è l'evento sulla sicurezza informatica più rilevante in **Spagna** e uno dei più importanti in **Europa**. Con **la missione di promuovere la conoscenza tecnica**, questo congresso è un punto di incontro fervente per i professionisti della tecnologia e della sicurezza informatica in ogni disciplina.

{% embed url="https://www.rootedcon.com/" %}

{% hint style="info" %}
Una nota su **PCAP** vs **PCAPNG**: ci sono due versioni del formato file PCAP; **PCAPNG è più recente e non supportato da tutti gli strumenti**. Potresti dover convertire un file da PCAPNG a PCAP usando Wireshark o un altro strumento compatibile, per poterlo utilizzare in altri strumenti.
{% endhint %}

## Strumenti online per pcaps

* Se l'intestazione del tuo pcap è **corrotta** dovresti provare a **ripararla** usando: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php)
* Estrarre **informazioni** e cercare **malware** all'interno di un pcap in [**PacketTotal**](https://packettotal.com)
* Cercare **attività malevole** utilizzando [**www.virustotal.com**](https://www.virustotal.com) e [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com)
* **Analisi completa del pcap dal browser su** [**https://apackets.com/**](https://apackets.com/)

## Estrarre Informazioni

I seguenti strumenti sono utili per estrarre statistiche, file, ecc.

### Wireshark

{% hint style="info" %}
**Se stai per analizzare un PCAP devi fondamentalmente sapere come usare Wireshark**
{% endhint %}

Puoi trovare alcuni trucchi di Wireshark in:

{% content-ref url="wireshark-tricks.md" %}
[wireshark-tricks.md](wireshark-tricks.md)
{% endcontent-ref %}

### [**https://apackets.com/**](https://apackets.com/)

Analisi pcap dal browser.

### Xplico Framework

[**Xplico** ](https://github.com/xplico/xplico)_(solo linux)_ può **analizzare** un **pcap** ed estrarre informazioni da esso. Ad esempio, da un file pcap, Xplico estrae ogni email (protocolli POP, IMAP e SMTP), tutti i contenuti HTTP, ogni chiamata VoIP (SIP), FTP, TFTP, e così via.

**Installazione**
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
Accedi a _**127.0.0.1:9876**_ con le credenziali _**xplico:xplico**_

Successivamente crea un **nuovo caso**, crea una **nuova sessione** all'interno del caso e **carica il file pcap**.

### NetworkMiner

Come Xplico, è uno strumento per **analizzare ed estrarre oggetti dai file pcap**. Ha una versione gratuita che puoi **scaricare** [**qui**](https://www.netresec.com/?page=NetworkMiner). Funziona con **Windows**.\
Questo strumento è anche utile per ottenere **altri tipi di informazioni analizzate** dai pacchetti al fine di poter sapere cosa stava accadendo in modo **più rapido**.

### NetWitness Investigator

Puoi scaricare [**NetWitness Investigator da qui**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(Funziona su Windows)**.\
Questo è un altro strumento utile che **analizza i pacchetti** e ordina le informazioni in modo utile per **sapere cosa sta accadendo all'interno**.

### [BruteShark](https://github.com/odedshimon/BruteShark)

* Estrarre e codificare nomi utente e password (HTTP, FTP, Telnet, IMAP, SMTP...)
* Estrarre hash di autenticazione e craccarli usando Hashcat (Kerberos, NTLM, CRAM-MD5, HTTP-Digest...)
* Creare un diagramma di rete visuale (Nodi di rete e utenti)
* Estrarre query DNS
* Ricostruire tutte le sessioni TCP e UDP
* Intaglio di file

### Capinfos
```
capinfos capture.pcap
```
### Ngrep

Se stai **cercando** qualcosa all'interno del file pcap, puoi utilizzare **ngrep**. Ecco un esempio che utilizza i filtri principali:
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Intaglio

Utilizzare le tecniche comuni di intaglio può essere utile per estrarre file e informazioni dal pcap:

{% content-ref url="../partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Cattura delle credenziali

È possibile utilizzare strumenti come [https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz) per analizzare le credenziali da un pcap o da un'interfaccia live.

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) è l'evento sulla sicurezza informatica più rilevante in **Spagna** e uno dei più importanti in **Europa**. Con **il compito di promuovere la conoscenza tecnica**, questo congresso è un punto di incontro fervente per i professionisti della tecnologia e della sicurezza informatica in ogni disciplina.

{% embed url="https://www.rootedcon.com/" %}

## Controlla Exploit/Malware

### Suricata

**Installazione e configurazione**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**Controlla il file pcap**
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) è uno strumento che

* Legge un file PCAP ed estrae flussi Http.
* sgonfia gzip qualsiasi flusso compresso
* Scansiona ogni file con yara
* Scrive un report.txt
* Opzionalmente salva i file corrispondenti in una cartella

### Analisi Malware

Controlla se riesci a trovare qualsiasi impronta di un malware conosciuto:

{% content-ref url="../malware-analysis.md" %}
[malware-analysis.md](../malware-analysis.md)
{% endcontent-ref %}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) è un analizzatore di traffico di rete passivo e open-source. Molti operatori utilizzano Zeek come Monitor di Sicurezza di Rete (NSM) per supportare le indagini su attività sospette o dannose. Zeek supporta anche una vasta gamma di compiti di analisi del traffico al di là del dominio della sicurezza, inclusa la misurazione delle prestazioni e la risoluzione dei problemi.

Fondamentalmente, i log creati da `zeek` non sono **pcap**. Pertanto sarà necessario utilizzare **altri strumenti** per analizzare i log dove sono presenti le **informazioni** sui pcap.
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
## Altri trucchi di analisi pcap

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

[**RootedCON**](https://www.rootedcon.com/) è l'evento più rilevante nel campo della sicurezza informatica in **Spagna** e uno dei più importanti in **Europa**. Con **la missione di promuovere la conoscenza tecnica**, questo congresso è un punto di incontro fervente per i professionisti della tecnologia e della sicurezza informatica in ogni disciplina.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF**, controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione esclusiva di [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
