<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre entreprise annoncée dans HackTricks ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe telegram**](https://t.me/peass) ou **suivez-moi** sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et au [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


# Invoke
```text
powershell -ep bypass
. .\powerup.ps
Invoke-AllChecks
```
# Vérifications

_03/2019_

* [x] Privilèges actuels
* [x] Chemins de service non entre guillemets
* [x] Autorisations d'exécution de service
* [x] Autorisations de service
* [x] %PATH% pour les emplacements de DLL pouvant être détournés
* [x] Clé de registre AlwaysInstallElevated
* [x] Identifiants Autologon dans le registre
* [x] Autoruns et configurations de registre modifiables
* [x] Fichiers/configurations schtask modifiables
* [x] Fichiers d'installation sans surveillance
* [x] Chaînes web.config chiffrées
* [x] Mots de passe de pool d'applications et de répertoire virtuel chiffrés
* [x] Mots de passe en texte brut dans McAfee SiteList.xml
* [x] Fichiers .xml de préférences de stratégie de groupe mis en cache
