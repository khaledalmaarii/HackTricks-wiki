# Wireshark tricks

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


## Améliorez vos compétences Wireshark

### Tutoriels

Les tutoriels suivants sont incroyables pour apprendre quelques astuces de base intéressantes :

* [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
* [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
* [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
* [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Informations analysées

**Informations Expert**

En cliquant sur _**Analyser** --> **Informations Expert**_, vous aurez un **aperçu** de ce qui se passe dans les paquets **analysés** :

![](<../../../.gitbook/assets/image (256).png>)

**Adresses Résolues**

Sous _**Statistiques --> Adresses Résolues**_, vous pouvez trouver plusieurs **informations** qui ont été "**résolues**" par Wireshark, comme le port/transport au protocole, le MAC au fabricant, etc. Il est intéressant de savoir ce qui est impliqué dans la communication.

![](<../../../.gitbook/assets/image (893).png>)

**Hiérarchie des Protocoles**

Sous _**Statistiques --> Hiérarchie des Protocoles**_, vous pouvez trouver les **protocoles** **impliqués** dans la communication et des données à leur sujet.

![](<../../../.gitbook/assets/image (586).png>)

**Conversations**

Sous _**Statistiques --> Conversations**_, vous pouvez trouver un **résumé des conversations** dans la communication et des données à leur sujet.

![](<../../../.gitbook/assets/image (453).png>)

**Points de terminaison**

Sous _**Statistiques --> Points de terminaison**_, vous pouvez trouver un **résumé des points de terminaison** dans la communication et des données sur chacun d'eux.

![](<../../../.gitbook/assets/image (896).png>)

**Informations DNS**

Sous _**Statistiques --> DNS**_, vous pouvez trouver des statistiques sur la requête DNS capturée.

![](<../../../.gitbook/assets/image (1063).png>)

**Graphique I/O**

Sous _**Statistiques --> Graphique I/O**_, vous pouvez trouver un **graphique de la communication.**

![](<../../../.gitbook/assets/image (992).png>)

### Filtres

Ici, vous pouvez trouver des filtres Wireshark selon le protocole : [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
D'autres filtres intéressants :

* `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
* Trafic HTTP et HTTPS initial
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
* Trafic HTTP et HTTPS initial + TCP SYN
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
* Trafic HTTP et HTTPS initial + TCP SYN + requêtes DNS

### Recherche

Si vous souhaitez **chercher** du **contenu** à l'intérieur des **paquets** des sessions, appuyez sur _CTRL+f_. Vous pouvez ajouter de nouvelles couches à la barre d'informations principale (No., Heure, Source, etc.) en appuyant sur le bouton droit puis sur modifier la colonne.

### Laboratoires pcap gratuits

**Pratiquez avec les défis gratuits de :** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identification des Domaines

Vous pouvez ajouter une colonne qui montre l'en-tête HTTP de l'hôte :

![](<../../../.gitbook/assets/image (639).png>)

Et une colonne qui ajoute le nom du serveur d'une connexion HTTPS initiée (**ssl.handshake.type == 1**):

![](<../../../.gitbook/assets/image (408) (1).png>)

## Identification des noms d'hôtes locaux

### Depuis DHCP

Dans la version actuelle de Wireshark, au lieu de `bootp`, vous devez rechercher `DHCP`

![](<../../../.gitbook/assets/image (1013).png>)

### Depuis NBNS

![](<../../../.gitbook/assets/image (1003).png>)

## Décryptage TLS

### Décryptage du trafic https avec la clé privée du serveur

_edit>préférences>protocole>ssl>_

![](<../../../.gitbook/assets/image (1103).png>)

Appuyez sur _Modifier_ et ajoutez toutes les données du serveur et la clé privée (_IP, Port, Protocole, Fichier de clé et mot de passe_)

### Décryptage du trafic https avec des clés de session symétriques

Firefox et Chrome ont la capacité de journaliser les clés de session TLS, qui peuvent être utilisées avec Wireshark pour déchiffrer le trafic TLS. Cela permet une analyse approfondie des communications sécurisées. Plus de détails sur la façon d'effectuer ce décryptage peuvent être trouvés dans un guide sur [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).

Pour détecter cela, recherchez dans l'environnement la variable `SSLKEYLOGFILE`

Un fichier de clés partagées ressemblera à ceci :

![](<../../../.gitbook/assets/image (820).png>)

Pour l'importer dans Wireshark, allez à \_modifier > préférences > protocole > ssl > et importez-le dans le nom de fichier du journal (Pre)-Master-Secret :

![](<../../../.gitbook/assets/image (989).png>)

## Communication ADB

Extraire un APK d'une communication ADB où l'APK a été envoyé :
```python
from scapy.all import *

pcap = rdpcap("final2.pcapng")

def rm_data(data):
splitted = data.split(b"DATA")
if len(splitted) == 1:
return data
else:
return splitted[0]+splitted[1][4:]

all_bytes = b""
for pkt in pcap:
if Raw in pkt:
a = pkt[Raw]
if b"WRTE" == bytes(a)[:4]:
all_bytes += rm_data(bytes(a)[24:])
else:
all_bytes += rm_data(bytes(a))
print(all_bytes)

f = open('all_bytes.data', 'w+b')
f.write(all_bytes)
f.close()
```
{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Formation Expert Red Team AWS (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Formation Expert Red Team GCP (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
