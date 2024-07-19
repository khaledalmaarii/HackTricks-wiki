# AD CS Account Persistence

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

**Ceci est un petit résumé des chapitres sur la persistance des machines de la recherche incroyable de [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**


## **Comprendre le vol de crédentiels d'utilisateur actif avec des certificats – PERSIST1**

Dans un scénario où un certificat permettant l'authentification de domaine peut être demandé par un utilisateur, un attaquant a l'opportunité de **demander** et de **voler** ce certificat pour **maintenir la persistance** sur un réseau. Par défaut, le modèle `User` dans Active Directory permet de telles demandes, bien qu'il puisse parfois être désactivé.

En utilisant un outil nommé [**Certify**](https://github.com/GhostPack/Certify), on peut rechercher des certificats valides qui permettent un accès persistant :
```bash
Certify.exe find /clientauth
```
Il est souligné qu'un certificat a du pouvoir grâce à sa capacité à **s'authentifier en tant qu'utilisateur** auquel il appartient, indépendamment de tout changement de mot de passe, tant que le certificat reste **valide**.

Les certificats peuvent être demandés via une interface graphique en utilisant `certmgr.msc` ou via la ligne de commande avec `certreq.exe`. Avec **Certify**, le processus de demande d'un certificat est simplifié comme suit :
```bash
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
Lors d'une demande réussie, un certificat ainsi que sa clé privée est généré au format `.pem`. Pour convertir cela en un fichier `.pfx`, qui est utilisable sur les systèmes Windows, la commande suivante est utilisée :
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
Le fichier `.pfx` peut ensuite être téléchargé sur un système cible et utilisé avec un outil appelé [**Rubeus**](https://github.com/GhostPack/Rubeus) pour demander un Ticket Granting Ticket (TGT) pour l'utilisateur, prolongeant l'accès de l'attaquant tant que le certificat est **valide** (généralement un an) :
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
Un avertissement important est partagé sur la façon dont cette technique, combinée avec une autre méthode décrite dans la section **THEFT5**, permet à un attaquant d'obtenir de manière persistante le **hash NTLM** d'un compte sans interagir avec le Local Security Authority Subsystem Service (LSASS), et depuis un contexte non élevé, offrant une méthode plus discrète pour le vol de crédentiels à long terme.

## **Gaining Machine Persistence with Certificates - PERSIST2**

Une autre méthode consiste à inscrire le compte machine d'un système compromis pour un certificat, en utilisant le modèle par défaut `Machine` qui permet de telles actions. Si un attaquant obtient des privilèges élevés sur un système, il peut utiliser le compte **SYSTEM** pour demander des certificats, fournissant une forme de **persistence** :
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
Cet accès permet à l'attaquant de s'authentifier auprès de **Kerberos** en tant que compte machine et d'utiliser **S4U2Self** pour obtenir des tickets de service Kerberos pour n'importe quel service sur l'hôte, accordant ainsi à l'attaquant un accès persistant à la machine.

## **Étendre la persistance par le renouvellement de certificat - PERSIST3**

La méthode finale discutée implique de tirer parti des **périodes de validité** et de **renouvellement** des modèles de certificat. En **renouvelant** un certificat avant son expiration, un attaquant peut maintenir l'authentification à Active Directory sans avoir besoin d'enrôlements de tickets supplémentaires, ce qui pourrait laisser des traces sur le serveur de l'Autorité de Certification (CA).

Cette approche permet une méthode de **persistance étendue**, minimisant le risque de détection grâce à moins d'interactions avec le serveur CA et évitant la génération d'artefacts qui pourraient alerter les administrateurs de l'intrusion.
