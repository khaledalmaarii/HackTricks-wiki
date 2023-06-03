# Clés de registre Windows intéressantes

## Clés de registre Windows intéressantes

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **Informations système Windows**

### Version

* **`Software\Microsoft\Windows NT\CurrentVersion`**: Version de Windows, Service Pack, heure d'installation et propriétaire enregistré

### Nom d'hôte

* **`System\ControlSet001\Control\ComputerName\ComputerName`**: Nom d'hôte

### Fuseau horaire

* **`System\ControlSet001\Control\TimeZoneInformation`**: Fuseau horaire

### Heure d'accès la plus récente

* **`System\ControlSet001\Control\Filesystem`**: Dernière heure d'accès (par défaut, elle est désactivée avec `NtfsDisableLastAccessUpdate=1`, si `0`, alors elle est activée).
  * Pour l'activer : `fsutil behavior set disablelastaccess 0`

### Heure d'arrêt

* `System\ControlSet001\Control\Windows` : Heure d'arrêt
* `System\ControlSet001\Control\Watchdog\Display` : Nombre d'arrêts (uniquement XP)

### Informations réseau

* **`System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}`**: Interfaces réseau
* **`Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged` & `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed`
