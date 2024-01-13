<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# Vérifier les BSSIDs

Lorsque vous recevez une capture dont le trafic principal est le Wifi en utilisant WireShark, vous pouvez commencer à enquêter sur tous les SSIDs de la capture avec _Wireless --> WLAN Traffic_ :

![](<../../../.gitbook/assets/image (424).png>)

![](<../../../.gitbook/assets/image (425).png>)

## Brute Force

Une des colonnes de cet écran indique si **une authentification a été trouvée dans le pcap**. Si c'est le cas, vous pouvez essayer de la forcer en utilisant `aircrack-ng` :
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Par exemple, il récupérera la phrase secrète WPA protégeant une PSK (clé pré-partagée), qui sera nécessaire pour déchiffrer le trafic plus tard.

# Données dans les Balises / Canal Latéral

Si vous soupçonnez que **des données fuient à l'intérieur des balises d'un réseau Wifi**, vous pouvez vérifier les balises du réseau en utilisant un filtre comme le suivant : `wlan contains <NOMduRESEAU>`, ou `wlan.ssid == "NOMduRESEAU"` recherchez à l'intérieur des paquets filtrés des chaînes de caractères suspectes.

# Trouver des Adresses MAC Inconnues dans Un Réseau Wifi

Le lien suivant sera utile pour trouver les **machines envoyant des données à l'intérieur d'un Réseau Wifi** :

* `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Si vous connaissez déjà **les adresses MAC, vous pouvez les retirer de la sortie** en ajoutant des vérifications comme celle-ci : `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Une fois que vous avez détecté des adresses **MAC inconnues** communiquant à l'intérieur du réseau, vous pouvez utiliser des **filtres** comme le suivant : `wlan.addr==<Adresse MAC> && (ftp || http || ssh || telnet)` pour filtrer son trafic. Notez que les filtres ftp/http/ssh/telnet sont utiles si vous avez déchiffré le trafic.

# Décrypter le Trafic

Éditer --> Préférences --> Protocoles --> IEEE 802.11--> Éditer

![](<../../../.gitbook/assets/image (426).png>)

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
