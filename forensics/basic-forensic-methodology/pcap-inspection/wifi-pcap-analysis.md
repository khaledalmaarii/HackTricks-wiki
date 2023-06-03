<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


# Vérifier les BSSIDs

Lorsque vous recevez une capture dont le trafic principal est Wifi en utilisant WireShark, vous pouvez commencer à enquêter sur tous les SSID de la capture avec _Wireless --> WLAN Traffic_ :

![](<../../../.gitbook/assets/image (424).png>)

![](<../../../.gitbook/assets/image (425).png>)

## Brute Force

L'une des colonnes de cet écran indique si **une authentification a été trouvée dans le pcap**. Si tel est le cas, vous pouvez essayer de la forcer en utilisant `aircrack-ng` :
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
# Données dans les balises / Canal latéral

Si vous soupçonnez que **des données sont en train de fuiter à l'intérieur des balises d'un réseau Wifi**, vous pouvez vérifier les balises du réseau en utilisant un filtre comme celui-ci : `wlan contains <NOMduRESEAU>`, ou `wlan.ssid == "NOMduRESEAU"` pour rechercher des chaînes suspectes dans les paquets filtrés.

# Trouver des adresses MAC inconnues dans un réseau Wifi

Le lien suivant sera utile pour trouver les **machines qui envoient des données à l'intérieur d'un réseau Wifi** :

* `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Si vous connaissez déjà les **adresses MAC, vous pouvez les supprimer de la sortie** en ajoutant des vérifications comme celle-ci : `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Une fois que vous avez détecté des **adresses MAC inconnues** communiquant à l'intérieur du réseau, vous pouvez utiliser des **filtres** comme celui-ci : `wlan.addr==<adresse MAC> && (ftp || http || ssh || telnet)` pour filtrer son trafic. Notez que les filtres ftp/http/ssh/telnet sont utiles si vous avez décrypté le trafic.

# Décrypter le trafic

Modifier --> Préférences --> Protocoles --> IEEE 802.11--> Modifier

![](<../../../.gitbook/assets/image (426).png>)





<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
