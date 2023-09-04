# Méthodologie de phishing

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Méthodologie

1. Faire de la reconnaissance sur la victime
1. Sélectionner le **domaine de la victime**.
2. Effectuer une **énumération web de base** en recherchant les portails de connexion utilisés par la victime et **décider** lequel vous allez **usurper**.
3. Utiliser des **OSINT** pour **trouver des adresses e-mail**.
2. Préparer l'environnement
1. **Acheter le domaine** que vous allez utiliser pour l'évaluation de phishing
2. **Configurer le service de messagerie** lié aux enregistrements (SPF, DMARC, DKIM, rDNS)
3. Configurer le VPS avec **gophish**
3. Préparer la campagne
1. Préparer le **modèle d'e-mail**
2. Préparer la **page web** pour voler les identifiants
4. Lancer la campagne !

## Générer des noms de domaine similaires ou acheter un domaine de confiance

### Techniques de variation de nom de domaine

* **Mot-clé** : Le nom de domaine **contient** un **mot-clé** important du domaine d'origine (par exemple, zelster.com-management.com).
* **Sous-domaine avec tiret** : Remplacer le **point par un tiret** dans un sous-domaine (par exemple, www-zelster.com).
* **Nouveau TLD** : Utiliser le même domaine avec un **nouveau TLD** (par exemple, zelster.org)
* **Homoglyphe** : Il **remplace** une lettre du nom de domaine par des lettres qui se ressemblent (par exemple, zelfser.com).
* **Transposition** : Il **échange deux lettres** dans le nom de domaine (par exemple, zelster.com).
* **Singulier/Pluriel** : Ajoute ou supprime un "s" à la fin du nom de domaine (par exemple, zeltsers.com).
* **Omission** : Il **supprime une** des lettres du nom de domaine (par exemple, zelser.com).
* **Répétition** : Il **répète une** des lettres du nom de domaine (par exemple, zeltsser.com).
* **Remplacement** : Comme un homoglyphe mais moins discret. Il remplace une des lettres du nom de domaine, peut-être par une lettre proche de la lettre d'origine sur le clavier (par exemple, zektser.com).
* **Sous-domaine** : Introduire un **point** à l'intérieur du nom de domaine (par exemple, ze.lster.com).
* **Insertion** : Il **insère une lettre** dans le nom de domaine (par exemple, zerltser.com).
* **Point manquant** : Ajouter le TLD au nom de domaine. (par exemple, zelstercom.com)

**Outils automatiques**

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Sites web**

* [https://dnstwist.it/](https://dnstwist.it)
* [https://dnstwister.report/](https://dnstwister.report)
* [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Dans le monde de l'informatique, tout est stocké en bits (zéros et uns) dans la mémoire en arrière-plan.\
Cela s'applique également aux domaines. Par exemple, _windows.com_ devient _01110111..._ dans la mémoire volatile de votre appareil informatique.\
Cependant, que se passe-t-il si l'un de ces bits est automatiquement inversé en raison d'une éruption solaire, de rayons cosmiques ou d'une erreur matérielle ? C'est-à-dire qu'un des 0 devient un 1 et vice versa.\
En appliquant ce concept à une requête DNS, il est possible que le **domaine demandé** qui arrive au serveur DNS **ne soit pas le même que le domaine initialement demandé**.

Par exemple, une modification d'un bit dans le domaine windows.com peut le transformer en _windnws.com._\
**Les attaquants peuvent enregistrer autant de domaines avec inversion de bits que possible liés à la victime afin de rediriger les utilisateurs légitimes vers leur infrastructure**.

Pour plus d'informations, consultez [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
### Acheter un domaine de confiance

Vous pouvez rechercher sur [https://www.expireddomains.net/](https://www.expireddomains.net) un domaine expiré que vous pourriez utiliser.\
Afin de vous assurer que le domaine expiré que vous allez acheter **a déjà un bon référencement SEO**, vous pouvez vérifier sa catégorisation sur :

* [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
* [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Découverte des adresses e-mail

* [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% gratuit)
* [https://phonebook.cz/](https://phonebook.cz) (100% gratuit)
* [https://maildb.io/](https://maildb.io)
* [https://hunter.io/](https://hunter.io)
* [https://anymailfinder.com/](https://anymailfinder.com)

Pour **découvrir davantage** d'adresses e-mail valides ou **vérifier celles** que vous avez déjà découvertes, vous pouvez vérifier si vous pouvez effectuer une attaque par force brute sur les serveurs SMTP de la victime. [Apprenez comment vérifier/découvrir une adresse e-mail ici](../../network-services-pentesting/pentesting-smtp/#username-bruteforce-enumeration).\
De plus, n'oubliez pas que si les utilisateurs utilisent **un portail web pour accéder à leurs e-mails**, vous pouvez vérifier s'il est vulnérable à une **attaque par force brute sur les noms d'utilisateur** et exploiter cette vulnérabilité si possible.

## Configuration de GoPhish

### Installation

Vous pouvez le télécharger depuis [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Téléchargez-le et décompressez-le dans `/opt/gophish` et exécutez `/opt/gophish/gophish`\
Un mot de passe pour l'utilisateur admin vous sera donné sur le port 3333 dans la sortie. Accédez donc à ce port et utilisez ces informations d'identification pour changer le mot de passe de l'admin. Vous devrez peut-être faire un tunnel sur ce port en local :
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configuration

**Configuration du certificat TLS**

Avant cette étape, vous devez **déjà avoir acheté le domaine** que vous allez utiliser et il doit être **redirigé** vers l'**adresse IP du VPS** où vous configurez **gophish**.
```bash
DOMAIN="<domain>"
wget https://dl.eff.org/certbot-auto
chmod +x certbot-auto
sudo apt install snapd
sudo snap install core
sudo snap refresh core
sudo apt-get remove certbot
sudo snap install --classic certbot
sudo ln -s /snap/bin/certbot /usr/bin/certbot
certbot certonly --standalone -d "$DOMAIN"
mkdir /opt/gophish/ssl_keys
cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" /opt/gophish/ssl_keys/key.pem
cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" /opt/gophish/ssl_keys/key.crt​
```
**Configuration du courrier électronique**

Commencez par installer : `apt-get install postfix`

Ensuite, ajoutez le domaine aux fichiers suivants :

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Modifiez également les valeurs des variables suivantes dans /etc/postfix/main.cf**

`myhostname = <domaine>`\
`mydestination = $myhostname, <domaine>, localhost.com, localhost`

Enfin, modifiez les fichiers **`/etc/hostname`** et **`/etc/mailname`** avec votre nom de domaine et **redémarrez votre VPS**.

Maintenant, créez un **enregistrement DNS A** de `mail.<domaine>` pointant vers l'**adresse IP** du VPS et un **enregistrement DNS MX** pointant vers `mail.<domaine>`.

Maintenant, testons l'envoi d'un courrier électronique :
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Configuration de Gophish**

Arrêtez l'exécution de Gophish et configurez-le.\
Modifiez `/opt/gophish/config.json` comme suit (notez l'utilisation de https) :
```bash
{
"admin_server": {
"listen_url": "127.0.0.1:3333",
"use_tls": true,
"cert_path": "gophish_admin.crt",
"key_path": "gophish_admin.key"
},
"phish_server": {
"listen_url": "0.0.0.0:443",
"use_tls": true,
"cert_path": "/opt/gophish/ssl_keys/key.crt",
"key_path": "/opt/gophish/ssl_keys/key.pem"
},
"db_name": "sqlite3",
"db_path": "gophish.db",
"migrations_prefix": "db/db_",
"contact_address": "",
"logging": {
"filename": "",
"level": ""
}
}
```
**Configurer le service gophish**

Afin de créer le service gophish de manière à ce qu'il puisse être démarré automatiquement et géré en tant que service, vous pouvez créer le fichier `/etc/init.d/gophish` avec le contenu suivant :
```bash
#!/bin/bash
# /etc/init.d/gophish
# initialization file for stop/start of gophish application server
#
# chkconfig: - 64 36
# description: stops/starts gophish application server
# processname:gophish
# config:/opt/gophish/config.json
# From https://github.com/gophish/gophish/issues/586

# define script variables

processName=Gophish
process=gophish
appDirectory=/opt/gophish
logfile=/var/log/gophish/gophish.log
errfile=/var/log/gophish/gophish.error

start() {
echo 'Starting '${processName}'...'
cd ${appDirectory}
nohup ./$process >>$logfile 2>>$errfile &
sleep 1
}

stop() {
echo 'Stopping '${processName}'...'
pid=$(/bin/pidof ${process})
kill ${pid}
sleep 1
}

status() {
pid=$(/bin/pidof ${process})
if [["$pid" != ""| "$pid" != "" ]]; then
echo ${processName}' is running...'
else
echo ${processName}' is not running...'
fi
}

case $1 in
start|stop|status) "$1" ;;
esac
```
Terminez la configuration du service et vérifiez-le en effectuant les étapes suivantes :
```bash
mkdir /var/log/gophish
chmod +x /etc/init.d/gophish
update-rc.d gophish defaults
#Check the service
service gophish start
service gophish status
ss -l | grep "3333\|443"
service gophish stop
```
## Configuration du serveur de messagerie et du domaine

### Attendez

Plus un domaine est ancien, moins il est probable qu'il soit considéré comme du spam. Vous devriez donc attendre le plus longtemps possible (au moins 1 semaine) avant l'évaluation du phishing.\
Notez que même si vous devez attendre une semaine, vous pouvez terminer la configuration dès maintenant.

### Configuration de l'enregistrement DNS inversé (rDNS)

Définissez un enregistrement rDNS (PTR) qui résout l'adresse IP du VPS en nom de domaine.

### Enregistrement de la politique de l'expéditeur (SPF)

Vous devez **configurer un enregistrement SPF pour le nouveau domaine**. Si vous ne savez pas ce qu'est un enregistrement SPF, [**lisez cette page**](../../network-services-pentesting/pentesting-smtp/#spf).

Vous pouvez utiliser [https://www.spfwizard.net/](https://www.spfwizard.net) pour générer votre politique SPF (utilisez l'adresse IP de la machine VPS)

![](<../../.gitbook/assets/image (388).png>)

Voici le contenu qui doit être défini dans un enregistrement TXT à l'intérieur du domaine :
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Enregistrement Domain-based Message Authentication, Reporting & Conformance (DMARC)

Vous devez **configurer un enregistrement DMARC pour le nouveau domaine**. Si vous ne savez pas ce qu'est un enregistrement DMARC, [**lisez cette page**](../../network-services-pentesting/pentesting-smtp/#dmarc).

Vous devez créer un nouvel enregistrement DNS TXT pointant vers le nom d'hôte `_dmarc.<domaine>` avec le contenu suivant :
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Vous devez **configurer un DKIM pour le nouveau domaine**. Si vous ne savez pas ce qu'est un enregistrement DMARC, [**lisez cette page**](../../network-services-pentesting/pentesting-smtp/#dkim).

Ce tutoriel est basé sur : [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

{% hint style="info" %}
Vous devez concaténer les deux valeurs B64 que génère la clé DKIM :
```
v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
```
{% endhint %}

### Testez votre score de configuration d'email

Vous pouvez le faire en utilisant [https://www.mail-tester.com/](https://www.mail-tester.com)\
Accédez simplement à la page et envoyez un email à l'adresse qu'ils vous donnent :
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Vous pouvez également vérifier votre configuration de messagerie en envoyant un e-mail à `check-auth@verifier.port25.com` et en lisant la réponse (pour cela, vous devrez ouvrir le port 25 et consulter la réponse dans le fichier _/var/mail/root_ si vous envoyez l'e-mail en tant que root).\
Vérifiez que vous réussissez tous les tests :
```bash
==========================================================
Summary of Results
==========================================================
SPF check:          pass
DomainKeys check:   neutral
DKIM check:         pass
Sender-ID check:    pass
SpamAssassin check: ham
```
Alternativement, vous pouvez envoyer un **message à une adresse Gmail que vous contrôlez**, **afficher** les **en-têtes de l'email** reçu dans votre boîte de réception Gmail, `dkim=pass` doit être présent dans le champ d'en-tête `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Suppression de la liste noire de Spamhouse

La page www.mail-tester.com peut vous indiquer si votre domaine est bloqué par Spamhouse. Vous pouvez demander la suppression de votre domaine/IP sur : [https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Suppression de la liste noire de Microsoft

Vous pouvez demander la suppression de votre domaine/IP sur [https://sender.office.com/](https://sender.office.com).

## Créer et lancer une campagne GoPhish

### Profil d'envoi

* Définissez un **nom pour identifier** le profil de l'expéditeur
* Décidez à partir de quel compte vous allez envoyer les e-mails de phishing. Suggestions : _noreply, support, servicedesk, salesforce..._
* Vous pouvez laisser les champs nom d'utilisateur et mot de passe vides, mais assurez-vous de cocher "Ignorer les erreurs de certificat"

![](<../../.gitbook/assets/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (17).png>)

{% hint style="info" %}
Il est recommandé d'utiliser la fonctionnalité "**Envoyer un e-mail de test**" pour vérifier que tout fonctionne correctement.\
Je recommande d'**envoyer les e-mails de test à des adresses 10min mails** afin d'éviter d'être mis sur liste noire lors des tests.
{% endhint %}

### Modèle d'e-mail

* Définissez un **nom pour identifier** le modèle
* Ensuite, écrivez un **sujet** (rien d'étrange, juste quelque chose que vous pourriez vous attendre à lire dans un e-mail normal)
* Assurez-vous d'avoir coché "**Ajouter une image de suivi**"
* Rédigez le **modèle d'e-mail** (vous pouvez utiliser des variables comme dans l'exemple suivant) :
```markup
<html>
<head>
<title></title>
</head>
<body>
<p class="MsoNormal"><span style="font-size:10.0pt;font-family:&quot;Verdana&quot;,sans-serif;color:black">Dear {{.FirstName}} {{.LastName}},</span></p>

<p class="MsoNormal"><span style="font-size:10.0pt;font-family:&quot;Verdana&quot;,sans-serif;color:black">As you may be aware, due to the large number of employees working from home, the "PLATFORM NAME" platform is being migrated to a new domain with an improved and more secure version. To finalize account migration, please use the following link to log into the new HR portal and move your account to the new site: <a href="{{.URL}}"> "PLATFORM NAME" login portal </a><br />
<br />
Please Note: We require all users to move their accounts by 04/01/2021. Failure to confirm account migration may prevent you from logging into the application after the migration process is complete.<br />
<br />
Regards,</span></p>

WRITE HERE SOME SIGNATURE OF SOMEONE FROM THE COMPANY

<p>{{.Tracker}}</p>
</body>
</html>
```
Notez que **afin d'augmenter la crédibilité de l'e-mail**, il est recommandé d'utiliser une signature provenant d'un e-mail du client. Suggestions :

* Envoyez un e-mail à une **adresse inexistante** et vérifiez si la réponse contient une signature.
* Recherchez des e-mails **publics** tels que info@ex.com ou press@ex.com ou public@ex.com et envoyez-leur un e-mail en attendant la réponse.
* Essayez de contacter un e-mail **valide découvert** et attendez la réponse.

![](<../../.gitbook/assets/image (393).png>)

{% hint style="info" %}
Le modèle d'e-mail permet également de **joindre des fichiers à envoyer**. Si vous souhaitez également voler des défis NTLM en utilisant des fichiers/documents spécialement conçus, [lisez cette page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).
{% endhint %}

### Page d'atterrissage

* Écrivez un **nom**
* **Écrivez le code HTML** de la page web. Notez que vous pouvez **importer** des pages web.
* Cochez **Capture des données soumises** et **Capture des mots de passe**
* Définissez une **redirection**

![](<../../.gitbook/assets/image (394).png>)

{% hint style="info" %}
Généralement, vous devrez modifier le code HTML de la page et effectuer des tests en local (peut-être en utilisant un serveur Apache) **jusqu'à ce que vous obteniez les résultats souhaités**. Ensuite, écrivez ce code HTML dans la zone prévue à cet effet.\
Notez que si vous avez besoin d'**utiliser des ressources statiques** pour le HTML (peut-être des pages CSS et JS), vous pouvez les enregistrer dans _**/opt/gophish/static/endpoint**_ puis y accéder depuis _**/static/\<nom du fichier>**_
{% endhint %}

{% hint style="info" %}
Pour la redirection, vous pouvez **rediriger les utilisateurs vers la véritable page web principale** de la victime, ou les rediriger vers _/static/migration.html_ par exemple, mettre une **roue tournante** ([**https://loading.io/**](https://loading.io)) pendant 5 secondes, puis indiquer que le processus a réussi.
{% endhint %}

### Utilisateurs et groupes

* Définissez un nom
* **Importez les données** (notez que pour utiliser le modèle de l'exemple, vous avez besoin du prénom, du nom de famille et de l'adresse e-mail de chaque utilisateur)

![](<../../.gitbook/assets/image (395).png>)

### Campagne

Enfin, créez une campagne en sélectionnant un nom, le modèle d'e-mail, la page d'atterrissage, l'URL, le profil d'envoi et le groupe. Notez que l'URL sera le lien envoyé aux victimes.

Notez que le **profil d'envoi permet d'envoyer un e-mail de test pour voir à quoi ressemblera l'e-mail de phishing final** :

![](<../../.gitbook/assets/image (396).png>)

{% hint style="info" %}
Je recommande d'**envoyer les e-mails de test à des adresses 10min mails** afin d'éviter d'être mis sur liste noire lors des tests.
{% endhint %}

Une fois que tout est prêt, lancez simplement la campagne !

## Clonage de site web

Si, pour une raison quelconque, vous souhaitez cloner le site web, consultez la page suivante :

{% content-ref url="clone-a-website.md" %}
[clone-a-website.md](clone-a-website.md)
{% endcontent-ref %}

## Documents et fichiers compromis

Dans certaines évaluations de phishing (principalement pour les équipes Red), vous voudrez également **envoyer des fichiers contenant une sorte de porte dérobée** (peut-être un C2 ou simplement quelque chose qui déclenchera une authentification).\
Consultez la page suivante pour quelques exemples :

{% content-ref url="phishing-documents.md" %}
[phishing-documents.md](phishing-documents.md)
{% endcontent-ref %}

## Phishing MFA

### Via Proxy MitM

L'attaque précédente est assez astucieuse car vous simulez un vrai site web et collectez les informations saisies par l'utilisateur. Malheureusement, si l'utilisateur n'a pas saisi le bon mot de passe ou si l'application que vous avez simulée est configurée avec une authentification à deux facteurs (2FA), **ces informations ne vous permettront pas de vous faire passer pour l'utilisateur trompé**.

C'est là que des outils comme [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) et [**muraena**](https://github.com/muraenateam/muraena) sont utiles. Cet outil vous permettra de générer une attaque de type MitM. Fondamentalement, l'attaque fonctionne de la manière suivante :

1. Vous **usurpez le formulaire de connexion** de la vraie page web.
2. L'utilisateur **envoie** ses **informations d'identification** à votre fausse page et l'outil les envoie à la vraie page web, **vérifiant si les informations d'identification sont valides**.
3. Si le compte est configuré avec **2FA**, la page MitM demandera cette information et une fois que l'utilisateur l'aura saisie, l'outil l'enverra à la vraie page web.
4. Une fois que l'utilisateur est authentifié, vous (en tant qu'attaquant) aurez **capturé les informations d'identification, le 2FA, le cookie et toute autre information** de chaque interaction pendant que l'outil effectue une attaque MitM.

### Via VNC

Et si, au lieu d'**envoyer la victime vers une page malveillante** ayant la même apparence que l'originale, vous l'envoyez vers une **session VNC avec un navigateur connecté à la vraie page web** ? Vous pourrez voir ce qu'il fait, voler le mot de passe, le MFA utilisé, les cookies...\
Vous pouvez le faire avec [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Détection de la détection

De toute évidence, l'une des meilleures façons de savoir si vous avez été découvert est de **rechercher votre domaine dans les listes noires**. S'il apparaît dans une liste, votre domaine a été détecté comme suspect.\
Un moyen facile de vérifier si votre domaine apparaît dans une liste noire consiste à utiliser [https://malwareworld.com/](https://malwareworld.com)

Cependant, il existe d'autres moyens de savoir si la victime **cherche activement des activités de phishing suspectes** dans la nature, comme expliqué dans :

{% content-ref url="detecting-phising.md" %}
[detecting-phising.md](detecting-phising.md)
{% endcontent-ref %}

Vous pouvez **acheter un domaine avec un nom très similaire** à celui de la victime **et/ou générer un certificat** pour un **sous-domaine** d'un domaine que vous contrôlez **contenant** le **mot-clé** du domaine de la victime. Si la **victime** effectue une **interaction DNS ou HTTP** avec eux, vous saurez qu'elle **cherche activement** des domaines suspects et vous devrez être très discret.

### Évaluer le phishing

Utilisez [**Phishious** ](https://github.com/Rices/Phishious) pour évaluer si votre e-mail va se retrouver dans le dossier spam, s'il va être bloqué ou réussir.
## Références

* [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
* [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
* [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
