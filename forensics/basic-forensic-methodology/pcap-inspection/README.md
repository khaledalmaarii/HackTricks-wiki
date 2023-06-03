# Inspection de Pcap

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) est l'événement de cybersécurité le plus pertinent en **Espagne** et l'un des plus importants en **Europe**. Avec **pour mission de promouvoir les connaissances techniques**, ce congrès est un point de rencontre bouillonnant pour les professionnels de la technologie et de la cybersécurité dans toutes les disciplines.

{% embed url="https://www.rootedcon.com/" %}

{% hint style="info" %}
Une note sur **PCAP** vs **PCAPNG** : il existe deux versions du format de fichier PCAP ; **PCAPNG est plus récent et n'est pas pris en charge par tous les outils**. Vous devrez peut-être convertir un fichier de PCAPNG en PCAP à l'aide de Wireshark ou d'un autre outil compatible, afin de travailler avec lui dans d'autres outils.
{% endhint %}

## Outils en ligne pour les pcaps

* Si l'en-tête de votre pcap est **cassé**, vous devriez essayer de le **réparer** en utilisant : [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php)
* Extraire des **informations** et rechercher des **malwares** à l'intérieur d'un pcap sur [**PacketTotal**](https://packettotal.com)
* Rechercher une **activité malveillante** en utilisant [**www.virustotal.com**](https://www.virustotal.com) et [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com)

## Extraire des informations

Les outils suivants sont utiles pour extraire des statistiques, des fichiers, etc.

### Wireshark

{% hint style="info" %}
**Si vous allez analyser un PCAP, vous devez essentiellement savoir comment utiliser Wireshark**
{% endhint %}

Vous pouvez trouver quelques astuces Wireshark dans :

{% content-ref url="wireshark-tricks.md" %}
[wireshark-tricks.md](wireshark-tricks.md)
{% endcontent-ref %}

### Cadre Xplico

[**Xplico** ](https://github.com/xplico/xplico)_(uniquement linux)_ peut **analyser** un **pcap** et extraire des informations à partir de celui-ci. Par exemple, à partir d'un fichier pcap, Xplico extrait chaque e-mail (protocoles POP, IMAP et SMTP), tous les contenus HTTP, chaque appel VoIP (SIP), FTP, TFTP, etc.

**Installer**
```bash
sudo bash -c 'echo "deb http://repo.xplico.org/ $(lsb_release -s -c) main" /etc/apt/sources.list'
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 791C25CE
sudo apt-get update
sudo apt-get install xplico
```
**Exécuter**
```
/etc/init.d/apache2 restart
/etc/init.d/xplico start
```
Accédez à _**127.0.0.1:9876**_ avec les identifiants _**xplico:xplico**_

Ensuite, créez un **nouveau dossier**, créez une **nouvelle session** dans le dossier et **téléchargez le fichier pcap**.

### NetworkMiner

Comme Xplico, c'est un outil pour **analyser et extraire des objets des pcaps**. Il a une édition gratuite que vous pouvez **télécharger** [**ici**](https://www.netresec.com/?page=NetworkMiner). Il fonctionne avec **Windows**.\
Cet outil est également utile pour obtenir **d'autres informations analysées** à partir des paquets afin de pouvoir savoir ce qui se passait de manière **plus rapide**.

### NetWitness Investigator

Vous pouvez télécharger [**NetWitness Investigator ici**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(Il fonctionne sous Windows)**.\
C'est un autre outil utile qui **analyse les paquets** et trie les informations de manière utile pour **savoir ce qui se passe à l'intérieur**.

![](<../../../.gitbook/assets/image (567) (1).png>)

### [BruteShark](https://github.com/odedshimon/BruteShark)

* Extraction et encodage des noms d'utilisateur et des mots de passe (HTTP, FTP, Telnet, IMAP, SMTP...)
* Extraire les hachages d'authentification et les craquer en utilisant Hashcat (Kerberos, NTLM, CRAM-MD5, HTTP-Digest...)
* Construire un diagramme de réseau visuel (nœuds et utilisateurs du réseau)
* Extraire les requêtes DNS
* Reconstituer toutes les sessions TCP et UDP
* Sculpture de fichiers

### Capinfos
```
capinfos capture.pcap
```
### Ngrep

Si vous cherchez quelque chose à l'intérieur du pcap, vous pouvez utiliser **ngrep**. Voici un exemple utilisant les filtres principaux :
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Carving

L'utilisation de techniques courantes de carving peut être utile pour extraire des fichiers et des informations du pcap :

{% content-ref url="../partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Capture de mots de passe

Vous pouvez utiliser des outils tels que [https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz) pour extraire des mots de passe à partir d'un pcap ou d'une interface en direct.

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) est l'événement le plus pertinent en matière de cybersécurité en **Espagne** et l'un des plus importants en **Europe**. Avec **pour mission de promouvoir les connaissances techniques**, ce congrès est un point de rencontre bouillonnant pour les professionnels de la technologie et de la cybersécurité dans toutes les disciplines.

{% embed url="https://www.rootedcon.com/" %}

## Vérification des exploits/malwares

### Suricata

**Installation et configuration**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**Vérifier le fichier pcap**

---

Le fichier pcap est un format de fichier utilisé pour enregistrer les données de trafic réseau. Il est souvent utilisé pour l'analyse de réseau et la résolution de problèmes. Pour vérifier un fichier pcap, vous pouvez utiliser des outils tels que Wireshark ou tcpdump.

Voici les étapes à suivre pour vérifier un fichier pcap avec Wireshark :

1. Ouvrez Wireshark et cliquez sur "File" dans la barre de menu supérieure.
2. Sélectionnez "Open" et naviguez jusqu'au fichier pcap que vous souhaitez vérifier.
3. Une fois le fichier ouvert, vous pouvez voir les paquets de données enregistrés dans le fichier pcap.
4. Utilisez les filtres de Wireshark pour affiner votre analyse et trouver des informations spécifiques.

Il est important de noter que l'analyse de fichiers pcap peut révéler des informations sensibles telles que des mots de passe en clair ou des données personnelles. Assurez-vous de prendre les précautions nécessaires pour protéger ces informations sensibles.
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) est un outil qui

* Lit un fichier PCAP et extrait les flux Http.
* Décompresse gzip tous les flux compressés
* Analyse chaque fichier avec yara
* Écrit un rapport.txt
* Enregistre éventuellement les fichiers correspondants dans un répertoire

### Analyse de Malware

Vérifiez si vous pouvez trouver une empreinte digitale d'un malware connu:

{% content-ref url="../malware-analysis.md" %}
[malware-analysis.md](../malware-analysis.md)
{% endcontent-ref %}

## Zeek

> Zeek est un analyseur de trafic réseau passif et open-source. De nombreux opérateurs utilisent Zeek comme moniteur de sécurité réseau (NSM) pour soutenir les enquêtes sur des activités suspectes ou malveillantes. Zeek prend également en charge un large éventail de tâches d'analyse de trafic au-delà du domaine de la sécurité, notamment la mesure des performances et le dépannage.

En gros, les journaux créés par `zeek` ne sont pas des **pcaps**. Par conséquent, vous devrez utiliser **d'autres outils** pour analyser les journaux où se trouvent les **informations** sur les pcaps.
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
### Informations DNS
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
## Autres astuces d'analyse de pcap

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

[**RootedCON**](https://www.rootedcon.com/) est l'événement de cybersécurité le plus pertinent en **Espagne** et l'un des plus importants en **Europe**. Avec **pour mission de promouvoir les connaissances techniques**, ce congrès est un point de rencontre bouillonnant pour les professionnels de la technologie et de la cybersécurité dans toutes les disciplines.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
