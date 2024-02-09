# Persistance du compte AD CS

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

**Il s'agit d'un bref résumé des chapitres sur la persistance de la machine de la recherche impressionnante de [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**

## **Comprendre le vol de crédential utilisateur actif avec des certificats - PERSIST1**

Dans un scénario où un certificat permettant l'authentification de domaine peut être demandé par un utilisateur, un attaquant a l'opportunité de **demander** et **voler** ce certificat pour **maintenir la persistance** sur un réseau. Par défaut, le modèle `Utilisateur` dans Active Directory autorise de telles demandes, bien qu'elles puissent parfois être désactivées.

En utilisant un outil nommé [**Certify**](https://github.com/GhostPack/Certify), on peut rechercher des certificats valides permettant un accès persistant :
```bash
Certify.exe find /clientauth
```
Il est souligné que la puissance d'un certificat réside dans sa capacité à **s'authentifier en tant qu'utilisateur** auquel il appartient, indépendamment de tout changement de mot de passe, tant que le certificat reste **valide**.

Les certificats peuvent être demandés via une interface graphique en utilisant `certmgr.msc` ou en ligne de commande avec `certreq.exe`. Avec **Certify**, le processus de demande de certificat est simplifié comme suit :
```bash
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
Une fois la demande réussie, un certificat avec sa clé privée est généré au format `.pem`. Pour le convertir en fichier `.pfx`, utilisable sur les systèmes Windows, la commande suivante est utilisée :
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
Le fichier `.pfx` peut ensuite être téléchargé sur un système cible et utilisé avec un outil appelé [**Rubeus**](https://github.com/GhostPack/Rubeus) pour demander un Ticket Granting Ticket (TGT) pour l'utilisateur, prolongeant l'accès de l'attaquant aussi longtemps que le certificat est **valide** (généralement un an) :
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
Un avertissement important est partagé sur la façon dont cette technique, combinée à une autre méthode décrite dans la section **THEFT5**, permet à un attaquant d'obtenir de manière persistante le **hachage NTLM** d'un compte sans interagir avec le service sous-système d'autorité de sécurité locale (LSASS), et ce depuis un contexte non élevé, offrant ainsi une méthode plus discrète pour le vol de crédentials à long terme.

## **Obtention de la persistance sur la machine avec des certificats - PERSIST2**

Une autre méthode implique l'inscription du compte machine d'un système compromis pour un certificat, en utilisant le modèle par défaut `Machine` qui autorise de telles actions. Si un attaquant obtient des privilèges élevés sur un système, il peut utiliser le compte **SYSTEM** pour demander des certificats, offrant ainsi une forme de **persistance**:
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
Cet accès permet à l'attaquant de s'authentifier auprès de **Kerberos** en tant que compte machine et d'utiliser **S4U2Self** pour obtenir des tickets de service Kerberos pour n'importe quel service sur l'hôte, accordant ainsi à l'attaquant un accès persistant à la machine.

## **Extension de la persistance via le renouvellement de certificats - PERSIST3**

La méthode finale discutée implique de tirer parti de la **validité** et des **périodes de renouvellement** des modèles de certificats. En **renouvelant** un certificat avant son expiration, un attaquant peut maintenir l'authentification auprès de l'Active Directory sans avoir besoin d'inscriptions de tickets supplémentaires, ce qui pourrait laisser des traces sur le serveur d'Autorité de Certification (CA).

Cette approche permet une méthode de **persistance étendue**, réduisant le risque de détection grâce à moins d'interactions avec le serveur CA et en évitant la génération d'artefacts qui pourraient alerter les administrateurs de l'intrusion.

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks:

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
