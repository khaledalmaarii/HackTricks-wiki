# Astuces Wireshark

## Astuces Wireshark

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

- Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
- Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
- **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
- **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## Améliorez vos compétences Wireshark

### Tutoriels

Les tutoriels suivants sont excellents pour apprendre quelques astuces de base intéressantes :

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Informations analysées

**Informations d'expert**

En cliquant sur _**Analyser** --> **Informations d'expert**_, vous aurez un **aperçu** de ce qui se passe dans les paquets **analysés** :

![](<../../../.gitbook/assets/image (570).png>)

**Adresses résolues**

Sous _**Statistiques --> Adresses résolues**_, vous pouvez trouver plusieurs **informations** qui ont été "**résolues**" par Wireshark comme le port/transport au protocole, l'adresse MAC au fabricant, etc. Il est intéressant de savoir ce qui est impliqué dans la communication.

![](<../../../.gitbook/assets/image (571).png>)

**Hiérarchie des protocoles**

Sous _**Statistiques --> Hiérarchie des protocoles**_, vous pouvez trouver les **protocoles** **impliqués** dans la communication et des données à leur sujet.

![](<../../../.gitbook/assets/image (572).png>)

**Conversations**

Sous _**Statistiques --> Conversations**_, vous pouvez trouver un **résumé des conversations** dans la communication et des données à leur sujet.

![](<../../../.gitbook/assets/image (573).png>)

**Points finaux**

Sous _**Statistiques --> Points finaux**_, vous pouvez trouver un **résumé des points finaux** dans la communication et des données à leur sujet.

![](<../../../.gitbook/assets/image (575).png>)

**Infos DNS**

Sous _**Statistiques --> DNS**_, vous pouvez trouver des statistiques sur la requête DNS capturée.

![](<../../../.gitbook/assets/image (577).png>)

**Graphique E/S**

Sous _**Statistiques --> Graphique E/S**_, vous pouvez trouver un **graphique de la communication**.

![](<../../../.gitbook/assets/image (574).png>)

### Filtres

Ici, vous pouvez trouver des filtres Wireshark en fonction du protocole : [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Autres filtres intéressants :

- `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
- Trafic HTTP et HTTPS initial
- `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- Trafic HTTP et HTTPS initial + SYN TCP
- `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- Trafic HTTP et HTTPS initial + SYN TCP + requêtes DNS

### Recherche

Si vous souhaitez **rechercher** du **contenu** à l'intérieur des **paquets** des sessions, appuyez sur _CTRL+f_. Vous pouvez ajouter de nouvelles couches à la barre d'informations principale (N°, Heure, Source, etc.) en appuyant sur le bouton droit, puis sur modifier la colonne.

Pratique : [https://www.malware-traffic-analysis.net/](https://www.malware-traffic-analysis.net)

## Identification des domaines

Vous pouvez ajouter une colonne qui affiche l'en-tête Host HTTP :

![](<../../../.gitbook/assets/image (403).png>)

Et une colonne qui ajoute le nom du serveur à partir d'une connexion HTTPS initiale (**ssl.handshake.type == 1**):

![](<../../../.gitbook/assets/image (408) (1).png>)

## Identification des noms d'hôtes locaux

### À partir de DHCP

Dans Wireshark actuel, au lieu de `bootp`, vous devez rechercher `DHCP`

![](<../../../.gitbook/assets/image (404).png>)

### À partir de NBNS

![](<../../../.gitbook/assets/image (405).png>)

## Décryptage TLS

### Décryptage du trafic https avec la clé privée du serveur

_modifier>préférence>protocole>ssl>_

![](<../../../.gitbook/assets/image (98).png>)

Appuyez sur _Modifier_ et ajoutez toutes les données du serveur et de la clé privée (_IP, Port, Protocole, Fichier clé et mot de passe_)

### Décryptage du trafic https avec des clés de session symétriques

Il s'avère que Firefox et Chrome prennent en charge tous deux l'enregistrement de la clé de session symétrique utilisée pour chiffrer le trafic TLS dans un fichier. Vous pouvez ensuite pointer Wireshark vers ledit fichier et voilà ! trafic TLS déchiffré. Plus d'informations : [https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)\
Pour détecter cela, recherchez dans l'environnement la variable `SSLKEYLOGFILE`

Un fichier de clés partagées ressemblera à ceci :

![](<../../../.gitbook/assets/image (99).png>)

Pour importer ceci dans Wireshark, allez à \_modifier > préférence > protocole > ssl > et importez-le dans le fichier journal (Pré)-Master-Secret :

![](<../../../.gitbook/assets/image (100).png>)

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
<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

D'autres façons de soutenir HackTricks:

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
