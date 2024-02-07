# Méthodologie de Phishing

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## Méthodologie

1. Faire de la reconnaissance sur la victime
1. Sélectionner le **domaine de la victime**.
2. Effectuer une énumération web de base **en recherchant des portails de connexion** utilisés par la victime et **décider** lequel vous allez **usurper**.
3. Utiliser un peu d'**OSINT** pour **trouver des adresses e-mail**.
2. Préparer l'environnement
1. **Acheter le domaine** que vous allez utiliser pour l'évaluation du phishing
2. **Configurer le service de messagerie électronique** les enregistrements associés (SPF, DMARC, DKIM, rDNS)
3. Configurer le VPS avec **gophish**
3. Préparer la campagne
1. Préparer le **modèle d'e-mail**
2. Préparer la **page web** pour voler les identifiants
4. Lancer la campagne !

## Générer des noms de domaine similaires ou acheter un domaine de confiance

### Techniques de Variation de Nom de Domaine

* **Mot-clé** : Le nom de domaine **contient** un **mot-clé** important du domaine d'origine (par exemple, zelster.com-management.com).
* **Sous-domaine avec trait d'union** : Changer le **point pour un trait d'union** d'un sous-domaine (par exemple, www-zelster.com).
* **Nouvelle TLD** : Même domaine en utilisant une **nouvelle TLD** (par exemple, zelster.org)
* **Homoglyphe** : Il **remplace** une lettre dans le nom de domaine par des **lettres qui se ressemblent** (par exemple, zelfser.com).
* **Transposition** : Il **échange deux lettres** dans le nom de domaine (par exemple, zelster.com).
* **Singulier/Pluriel** : Ajoute ou supprime un "s" à la fin du nom de domaine (par exemple, zeltsers.com).
* **Omission** : Il **supprime une** des lettres du nom de domaine (par exemple, zelser.com).
* **Répétition** : Il **répète une** des lettres dans le nom de domaine (par exemple, zeltsser.com).
* **Remplacement** : Comme homoglyphe mais moins discret. Il remplace une des lettres du nom de domaine, peut-être par une lettre à proximité de la lettre d'origine sur le clavier (par exemple, zektser.com).
* **Sous-domainé** : Introduire un **point** à l'intérieur du nom de domaine (par exemple, ze.lster.com).
* **Insertion** : Il **insère une lettre** dans le nom de domaine (par exemple, zerltser.com).
* **Point manquant** : Ajouter la TLD au nom de domaine. (par exemple, zelstercom.com)

**Outils Automatiques**

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Sites Web**

* [https://dnstwist.it/](https://dnstwist.it)
* [https://dnstwister.report/](https://dnstwister.report)
* [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Inversion de Bits

Il existe une **possibilité qu'un ou plusieurs bits stockés ou en communication soient automatiquement inversés** en raison de divers facteurs tels que les éruptions solaires, les rayons cosmiques ou les erreurs matérielles.

Lorsque ce concept est **appliqué aux requêtes DNS**, il est possible que le **domaine reçu par le serveur DNS** ne soit pas le même que le domaine initialement demandé.

Par exemple, une modification d'un seul bit dans le domaine "windows.com" peut le changer en "windnws.com."

Les attaquants peuvent **en profiter en enregistrant plusieurs domaines avec inversion de bits** similaires au domaine de la victime. Leur intention est de rediriger les utilisateurs légitimes vers leur propre infrastructure.

Pour plus d'informations, consultez [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Acheter un domaine de confiance

Vous pouvez rechercher sur [https://www.expireddomains.net/](https://www.expireddomains.net) un domaine expiré que vous pourriez utiliser.\
Pour vous assurer que le domaine expiré que vous allez acheter **a déjà un bon référencement SEO**, vous pouvez vérifier comment il est catégorisé dans :

* [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
* [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Découverte des Adresses E-mail

* [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% gratuit)
* [https://phonebook.cz/](https://phonebook.cz) (100% gratuit)
* [https://maildb.io/](https://maildb.io)
* [https://hunter.io/](https://hunter.io)
* [https://anymailfinder.com/](https://anymailfinder.com)

Pour **découvrir plus** d'adresses e-mail valides ou **vérifier celles** que vous avez déjà découvertes, vous pouvez vérifier si vous pouvez les brute-forcer sur les serveurs smtp de la victime. [Apprenez comment vérifier/découvrir une adresse e-mail ici](../../network-services-pentesting/pentesting-smtp/#username-bruteforce-enumeration).\
De plus, n'oubliez pas que si les utilisateurs utilisent **un portail web pour accéder à leurs e-mails**, vous pouvez vérifier s'il est vulnérable à une **brute force de nom d'utilisateur**, et exploiter la vulnérabilité si possible.

## Configuration de GoPhish

### Installation

Vous pouvez le télécharger depuis [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Téléchargez-le et décompressez-le dans `/opt/gophish` et exécutez `/opt/gophish/gophish`\
Vous recevrez un mot de passe pour l'utilisateur admin sur le port 3333 dans la sortie. Par conséquent, accédez à ce port et utilisez ces informations d'identification pour changer le mot de passe admin. Vous devrez peut-être tunneliser ce port en local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configuration

**Configuration du certificat TLS**

Avant cette étape, vous devez **déjà avoir acheté le domaine** que vous allez utiliser et il doit être **redirigé** vers l'**IP du VPS** où vous configurez **gophish**.
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
**Configuration de messagerie**

Commencez par installer : `apt-get install postfix`

Ensuite, ajoutez le domaine aux fichiers suivants :

* **/etc/postfix/virtual\_domains**
* **/etc/postfix/transport**
* **/etc/postfix/virtual\_regexp**

**Modifiez également les valeurs des variables suivantes dans /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Enfin, modifiez les fichiers **`/etc/hostname`** et **`/etc/mailname`** avec votre nom de domaine et **redémarrez votre VPS.**

Maintenant, créez un **enregistrement A DNS** de `mail.<domain>` pointant vers l'**adresse IP** du VPS et un **enregistrement MX DNS** pointant vers `mail.<domain>`

Maintenant, testons l'envoi d'un e-mail :
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Configuration de Gophish**

Arrêtez l'exécution de gophish et configurons-le.\
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

Pour créer le service gophish afin qu'il puisse être démarré automatiquement et géré en tant que service, vous pouvez créer le fichier `/etc/init.d/gophish` avec le contenu suivant :
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
Terminer la configuration du service et le vérifier en effectuant :
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

### Attendre et être légitime

Plus un domaine est ancien, moins il risque d'être considéré comme du spam. Vous devriez donc attendre le plus longtemps possible (au moins 1 semaine) avant l'évaluation du phishing. De plus, si vous créez une page sur un secteur réputé, la réputation obtenue sera meilleure.

Notez que même si vous devez attendre une semaine, vous pouvez terminer la configuration dès maintenant.

### Configurer l'enregistrement Reverse DNS (rDNS)

Définissez un enregistrement rDNS (PTR) qui résout l'adresse IP du VPS en nom de domaine.

### Enregistrement du cadre de politique de l'expéditeur (SPF)

Vous devez **configurer un enregistrement SPF pour le nouveau domaine**. Si vous ne savez pas ce qu'est un enregistrement SPF, [**lisez cette page**](../../network-services-pentesting/pentesting-smtp/#spf).

Vous pouvez utiliser [https://www.spfwizard.net/](https://www.spfwizard.net) pour générer votre politique SPF (utilisez l'IP de la machine VPS)

![](<../../.gitbook/assets/image (388).png>)

Voici le contenu qui doit être défini à l'intérieur d'un enregistrement TXT dans le domaine :
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Enregistrement Domain-based Message Authentication, Reporting & Conformance (DMARC)

Vous devez **configurer un enregistrement DMARC pour le nouveau domaine**. Si vous ne savez pas ce qu'est un enregistrement DMARC, [**lisez cette page**](../../network-services-pentesting/pentesting-smtp/#dmarc).

Vous devez créer un nouvel enregistrement DNS TXT pointant vers le nom d'hôte `_dmarc.<domain>` avec le contenu suivant:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Vous devez **configurer un DKIM pour le nouveau domaine**. Si vous ne savez pas ce qu'est un enregistrement DMARC, [**lisez cette page**](../../network-services-pentesting/pentesting-smtp/#dkim).

Ce tutoriel est basé sur : [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

{% hint style="info" %}
Vous devez concaténer les deux valeurs B64 que la clé DKIM génère :
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
Vous pouvez également **vérifier la configuration de votre e-mail** en envoyant un e-mail à `check-auth@verifier.port25.com` et **en lisant la réponse** (pour cela, vous devrez **ouvrir** le port **25** et voir la réponse dans le fichier _/var/mail/root_ si vous envoyez l'e-mail en tant que root).\
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
Vous pouvez également envoyer un **message à un Gmail sous votre contrôle**, et vérifier les **en-têtes de l'email** dans votre boîte de réception Gmail, `dkim=pass` devrait être présent dans le champ d'en-tête `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Suppression de la liste noire de Spamhouse

La page [www.mail-tester.com](www.mail-tester.com) peut vous indiquer si votre domaine est bloqué par Spamhouse. Vous pouvez demander la suppression de votre domaine/IP sur : [https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Suppression de la liste noire de Microsoft

Vous pouvez demander la suppression de votre domaine/IP sur [https://sender.office.com/](https://sender.office.com).

## Créer et Lancer une Campagne de Phishing avec GoPhish

### Profil d'Envoi

* Définir un **nom pour identifier** le profil de l'expéditeur
* Décider à partir de quel compte vous allez envoyer les e-mails de phishing. Suggestions : _noreply, support, servicedesk, salesforce..._
* Vous pouvez laisser vide le nom d'utilisateur et le mot de passe, mais assurez-vous de cocher Ignorer les Erreurs de Certificat

![](<../../.gitbook/assets/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (17).png>)

{% hint style="info" %}
Il est recommandé d'utiliser la fonctionnalité "**Envoyer un E-mail de Test**" pour vérifier que tout fonctionne.\
Je recommande d'**envoyer les e-mails de test aux adresses 10min mails** afin d'éviter d'être blacklisté lors des tests.
{% endhint %}

### Modèle d'E-mail

* Définir un **nom pour identifier** le modèle
* Ensuite, écrire un **sujet** (rien d'étrange, juste quelque chose que vous pourriez vous attendre à lire dans un e-mail régulier)
* Assurez-vous d'avoir coché "**Ajouter une Image de Suivi**"
* Rédigez le **modèle d'e-mail** (vous pouvez utiliser des variables comme dans l'exemple suivant) :
```markup
<html>
<head>
<title></title>
</head>
<body>
<p class="MsoNormal"><span style="font-size:10.0pt;font-family:&quot;Verdana&quot;,sans-serif;color:black">Dear {{.FirstName}} {{.LastName}},</span></p>
<br />
Note: We require all user to login an a very suspicios page before the end of the week, thanks!<br />
<br />
Regards,</span></p>

WRITE HERE SOME SIGNATURE OF SOMEONE FROM THE COMPANY

<p>{{.Tracker}}</p>
</body>
</html>
```
Notez que **pour augmenter la crédibilité de l'e-mail**, il est recommandé d'utiliser une signature provenant d'un e-mail du client. Suggestions :

* Envoyez un e-mail à une **adresse inexistante** et vérifiez si la réponse contient une signature.
* Recherchez des e-mails **publics** tels que info@ex.com ou press@ex.com ou public@ex.com et envoyez-leur un e-mail en attendant la réponse.
* Essayez de contacter **quelques e-mails valides découverts** et attendez la réponse.

![](<../../.gitbook/assets/image (393).png>)

{% hint style="info" %}
Le modèle d'e-mail permet également de **joindre des fichiers à envoyer**. Si vous souhaitez également voler des défis NTLM en utilisant des fichiers/documents spécialement conçus, [consultez cette page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).
{% endhint %}

### Page de Destination

* Écrivez un **nom**
* **Écrivez le code HTML** de la page web. Notez que vous pouvez **importer** des pages web.
* Cochez **Capturer les données soumises** et **Capturer les mots de passe**
* Définissez une **redirection**

![](<../../.gitbook/assets/image (394).png>)

{% hint style="info" %}
Généralement, vous devrez modifier le code HTML de la page et effectuer des tests en local (peut-être en utilisant un serveur Apache) **jusqu'à ce que vous obteniez les résultats souhaités**. Ensuite, écrivez ce code HTML dans la zone prévue.\
Notez que si vous avez besoin d'**utiliser des ressources statiques** pour le HTML (peut-être des pages CSS et JS), vous pouvez les enregistrer dans _**/opt/gophish/static/endpoint**_ et y accéder depuis _**/static/\<nom du fichier>**_
{% endhint %}

{% hint style="info" %}
Pour la redirection, vous pourriez **rediriger les utilisateurs vers la page web principale légitime** de la victime, ou les rediriger vers _/static/migration.html_ par exemple, mettre une **roue tournante** ([**https://loading.io/**](https://loading.io)) pendant 5 secondes, puis indiquer que le processus a été réussi.
{% endhint %}

### Utilisateurs & Groupes

* Définissez un nom
* **Importez les données** (notez que pour utiliser le modèle pour l'exemple, vous avez besoin du prénom, du nom de famille et de l'adresse e-mail de chaque utilisateur)

![](<../../.gitbook/assets/image (395).png>)

### Campagne

Enfin, créez une campagne en sélectionnant un nom, le modèle d'e-mail, la page de destination, l'URL, le profil d'envoi et le groupe. Notez que l'URL sera le lien envoyé aux victimes.

Notez que le **Profil d'envoi permet d'envoyer un e-mail de test pour voir à quoi ressemblera l'e-mail de phishing final** :

![](<../../.gitbook/assets/image (396).png>)

{% hint style="info" %}
Je recommanderais d'**envoyer les e-mails de test à des adresses de 10 minutes** afin d'éviter d'être mis sur liste noire lors des tests.
{% endhint %}

Une fois que tout est prêt, lancez simplement la campagne !

## Clonage de Site Web

Si pour une raison quelconque vous souhaitez cloner le site web, consultez la page suivante :

{% content-ref url="clone-a-website.md" %}
[clone-a-website.md](clone-a-website.md)
{% endcontent-ref %}

## Documents et Fichiers Piégés

Dans certaines évaluations de phishing (principalement pour les Red Teams), vous voudrez également **envoyer des fichiers contenant une sorte de backdoor** (peut-être un C2 ou simplement quelque chose qui déclenchera une authentification).\
Consultez la page suivante pour quelques exemples :

{% content-ref url="phishing-documents.md" %}
[phishing-documents.md](phishing-documents.md)
{% endcontent-ref %}

## Phishing MFA

### Via Proxy MitM

L'attaque précédente est assez astucieuse car vous imitez un vrai site web et recueillez les informations définies par l'utilisateur. Malheureusement, si l'utilisateur n'a pas saisi le bon mot de passe ou si l'application que vous avez imitée est configurée avec une authentification à deux facteurs, **ces informations ne vous permettront pas d'usurper l'utilisateur trompé**.

C'est là que des outils comme [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) et [**muraena**](https://github.com/muraenateam/muraena) sont utiles. Cet outil vous permettra de générer une attaque de type MitM. Fondamentalement, les attaques fonctionnent de la manière suivante :

1. Vous **imitez le formulaire de connexion** de la vraie page web.
2. L'utilisateur **envoie** ses **identifiants** à votre fausse page et l'outil les envoie à la vraie page web, **vérifiant si les identifiants fonctionnent**.
3. Si le compte est configuré avec **une authentification à deux facteurs**, la page MitM demandera cela et une fois que l'utilisateur l'aura introduit, l'outil l'enverra à la vraie page web.
4. Une fois que l'utilisateur est authentifié, vous (en tant qu'attaquant) aurez **capturé les identifiants, l'authentification à deux facteurs, le cookie et toute information** de chaque interaction pendant que l'outil effectue un MitM.

### Via VNC

Et si au lieu d'**envoyer la victime vers une page malveillante** avec le même aspect que l'original, vous l'envoyez vers une **session VNC avec un navigateur connecté à la vraie page web** ? Vous pourrez voir ce qu'il fait, voler le mot de passe, l'authentification à deux facteurs utilisée, les cookies...\
Vous pouvez le faire avec [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Détection de la détection

Évidemment, l'une des meilleures façons de savoir si vous avez été repéré est de **rechercher votre domaine dans les listes noires**. S'il apparaît répertorié, votre domaine a été détecté comme suspect d'une manière ou d'une autre.\
Une façon simple de vérifier si votre domaine apparaît dans une liste noire est d'utiliser [https://malwareworld.com/](https://malwareworld.com)

Cependant, il existe d'autres moyens de savoir si la victime recherche **activement des activités de phishing suspectes dans la nature**, comme expliqué dans :

{% content-ref url="detecting-phising.md" %}
[detecting-phising.md](detecting-phising.md)
{% endcontent-ref %}

Vous pouvez **acheter un domaine avec un nom très similaire** à celui du domaine de la victime **et/ou générer un certificat** pour un **sous-domaine** d'un domaine que vous contrôlez **contenant** le **mot-clé** du domaine de la victime. Si la **victime** effectue une sorte d'**interaction DNS ou HTTP** avec eux, vous saurez qu'**elle recherche activement** des domaines suspects et vous devrez être très discret.

### Évaluer le phishing

Utilisez [**Phishious** ](https://github.com/Rices/Phishious) pour évaluer si votre e-mail va finir dans le dossier de spam ou s'il sera bloqué ou réussi.

## Références

* [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
* [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
* [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
* [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez** 💬 le [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**dépôts Github HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
