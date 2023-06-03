## Persistence de compte AD CS

Si l'utilisateur est autorisé à demander un certificat qui permet l'authentification de domaine, un attaquant pourrait le demander et le voler pour maintenir la persistance.

Le modèle **`Utilisateur`** le permet et est activé par **défaut**. Cependant, il peut être désactivé. Ainsi, [**Certify**](https://github.com/GhostPack/Certify) vous permet de trouver des certificats valides pour persister :
```
Certify.exe find /clientauth
```
Notez qu'un **certificat peut être utilisé pour l'authentification** en tant qu'utilisateur tant que le certificat est **valide**, **même** si l'utilisateur **change** son **mot de passe**.

Depuis l'interface graphique, il est possible de demander un certificat avec `certmgr.msc` ou via la ligne de commande avec `certreq.exe`.

En utilisant [**Certify**](https://github.com/GhostPack/Certify), vous pouvez exécuter :
```
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
Le résultat sera un bloc de texte formaté en **certificat** + **clé privée** `.pem`.
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
Pour **utiliser ce certificat**, on peut ensuite **télécharger** le fichier `.pfx` sur une cible et **l'utiliser avec** [**Rubeus**](https://github.com/GhostPack/Rubeus) pour **demander un TGT** pour l'utilisateur inscrit, tant que le certificat est valide (la durée de vie par défaut est de 1 an):
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
{% hint style="warning" %}
Combinée à la technique décrite dans la section [**THEFT5**](certificate-theft.md#ntlm-credential-theft-via-pkinit-theft5), un attaquant peut également obtenir de manière persistante le **hachage NTLM du compte**, que l'attaquant pourrait utiliser pour s'authentifier via **pass-the-hash** ou **crack** pour obtenir le **mot de passe en clair**. \
Il s'agit d'une méthode alternative de **vol de longue durée de justificatifs d'identité** qui ne touche pas à LSASS et qui est possible à partir d'un **contexte non élevé**.
{% endhint %}

## Persistence de la machine via des certificats - PERSIST2

Si un modèle de certificat permettait aux **ordinateurs de domaine** d'être des principaux d'inscription, un attaquant pourrait **inscrire le compte de la machine d'un système compromis**. Le modèle **`Machine`** par défaut correspond à toutes ces caractéristiques.

Si un **attaquant élève les privilèges** sur le système compromis, l'attaquant peut utiliser le compte **SYSTEM** pour s'inscrire dans des modèles de certificats qui accordent des privilèges d'inscription aux comptes de machine (plus d'informations dans [**THEFT3**](certificate-theft.md#machine-certificate-theft-via-dpapi-theft3)).

Vous pouvez utiliser [**Certify**](https://github.com/GhostPack/Certify) pour obtenir un certificat pour le compte de la machine en élevant automatiquement le compte au niveau SYSTEM avec :
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
Notez qu'avec l'accès à un certificat de compte machine, l'attaquant peut ensuite s'**authentifier auprès de Kerberos** en tant que compte machine. En utilisant **S4U2Self**, un attaquant peut ensuite obtenir un **ticket de service Kerberos pour n'importe quel service sur l'hôte** (par exemple, CIFS, HTTP, RPCSS, etc.) en tant que n'importe quel utilisateur.

Cela donne finalement à une attaque une méthode de persistance de machine.

## Persistance de compte via le renouvellement de certificat - PERSIST3

Les modèles de certificats ont une **période de validité** qui détermine pendant combien de temps un certificat délivré peut être utilisé, ainsi qu'une **période de renouvellement** (généralement 6 semaines). C'est une fenêtre de **temps avant** l'expiration du certificat où un **compte peut le renouveler** auprès de l'autorité de certification émettrice.

Si un attaquant compromet un certificat capable d'authentification de domaine par le vol ou l'inscription malveillante, l'attaquant peut **s'authentifier auprès d'AD pendant la durée de la période de validité du certificat**. L'attaquant, cependant, peut **renouveler le certificat avant l'expiration**. Cela peut fonctionner comme une approche de **persistance étendue** qui **empêche la demande de tickets** supplémentaires, ce qui **peut laisser des artefacts** sur le serveur CA lui-même.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
