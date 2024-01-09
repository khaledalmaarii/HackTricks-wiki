# Persistance de compte AD CS

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-moi** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Vol d'identifiants d'utilisateur actif via des certificats – PERSIST1

Si l'utilisateur est autorisé à demander un certificat qui permet l'authentification de domaine, un attaquant pourrait **demander** et **voler** ce certificat pour **maintenir** la **persistance**.

Le modèle **`User`** permet cela et est disponible par **défaut**. Cependant, il pourrait être désactivé. Ainsi, [**Certify**](https://github.com/GhostPack/Certify) vous permet de trouver des certificats valides pour persister :
```
Certify.exe find /clientauth
```
Notez qu'un **certificat peut être utilisé pour l'authentification** en tant qu'utilisateur tant que le certificat est **valide**, **même** si l'utilisateur **change** son **mot de passe**.

Depuis l'**interface graphique**, il est possible de demander un certificat avec `certmgr.msc` ou via la ligne de commande avec `certreq.exe`.

En utilisant [**Certify**](https://github.com/GhostPack/Certify), vous pouvez exécuter :
```
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
Le résultat sera un bloc de texte formaté `.pem` contenant un **certificat** + une **clé privée**.
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
Pour **utiliser ce certificat**, on peut ensuite **téléverser** le `.pfx` sur une cible et **l'utiliser avec** [**Rubeus**](https://github.com/GhostPack/Rubeus) pour **demander un TGT** pour l'utilisateur inscrit, tant que le certificat est valide (la durée de vie par défaut est de 1 an) :
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
{% hint style="warning" %}
Associée à la technique décrite dans la section [**THEFT5**](certificate-theft.md#ntlm-credential-theft-via-pkinit-theft5), un attaquant peut également **obtenir de manière persistante le hash NTLM du compte**, que l'attaquant pourrait utiliser pour s'authentifier via **pass-the-hash** ou **cracker** pour obtenir le **mot de passe en clair**. \
C'est une méthode alternative de **vol de credentials à long terme** qui ne **touche pas LSASS** et est possible depuis un **contexte non privilégié.**
{% endhint %}

## Persistance de Machine via Certificats - PERSIST2

Si un modèle de certificat autorise les **Domain Computers** comme principaux d'inscription, un attaquant pourrait **inscrire le compte machine d'un système compromis**. Le modèle par défaut **`Machine`** correspond à toutes ces caractéristiques.

Si un **attaquant élève ses privilèges** sur un système compromis, il peut utiliser le compte **SYSTEM** pour s'inscrire à des modèles de certificats qui accordent des privilèges d'inscription aux comptes machine (plus d'informations dans [**THEFT3**](certificate-theft.md#machine-certificate-theft-via-dpapi-theft3)).

Vous pouvez utiliser [**Certify**](https://github.com/GhostPack/Certify) pour rassembler un certificat pour le compte machine en élevant automatiquement au SYSTEM avec :
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
Notez qu'avec un accès au certificat d'un compte machine, l'attaquant peut alors **s'authentifier à Kerberos** en tant que compte machine. En utilisant **S4U2Self**, un attaquant peut ensuite obtenir un **ticket de service Kerberos pour n'importe quel service sur l'hôte** (par exemple, CIFS, HTTP, RPCSS, etc.) en tant qu'utilisateur quelconque.

En fin de compte, cela donne à une attaque une méthode de persistance de machine.

## Persistance de compte via le renouvellement de certificat - PERSIST3

Les modèles de certificats ont une **Période de Validité** qui détermine combien de temps un certificat émis peut être utilisé, ainsi qu'une **Période de renouvellement** (habituellement 6 semaines). C'est une fenêtre de **temps avant** que le certificat **expire** où un **compte peut le renouveler** auprès de l'autorité de certification émettrice.

Si un attaquant compromet un certificat capable d'authentification de domaine par vol ou inscription malveillante, l'attaquant peut **s'authentifier à AD pour la durée de la période de validité du certificat**. Cependant, l'attaquant peut **renouveler le certificat avant son expiration**. Cela peut fonctionner comme une approche de **persistance étendue** qui **évite les demandes d'inscription de tickets supplémentaires**, ce qui **peut laisser des artefacts** sur le serveur CA lui-même.

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux repos github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
