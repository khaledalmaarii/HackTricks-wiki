# Méthodologie de Phishing

{% hint style="success" %}
Apprenez et pratiquez le Hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le Hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}

## Méthodologie

1. Reconnaître la victime
1. Sélectionner le **domaine de la victime**.
2. Effectuer une énumération web de base **à la recherche de portails de connexion** utilisés par la victime et **décider** lequel vous allez **imiter**.
3. Utiliser des **OSINT** pour **trouver des emails**.
2. Préparer l'environnement
1. **Acheter le domaine** que vous allez utiliser pour l'évaluation de phishing.
2. **Configurer le service email** et les enregistrements associés (SPF, DMARC, DKIM, rDNS).
3. Configurer le VPS avec **gophish**.
3. Préparer la campagne
1. Préparer le **modèle d'email**.
2. Préparer la **page web** pour voler les identifiants.
4. Lancer la campagne !

## Générer des noms de domaine similaires ou acheter un domaine de confiance

### Techniques de Variation de Noms de Domaine

* **Mot-clé** : Le nom de domaine **contient** un **mot-clé** important du domaine original (par exemple, zelster.com-management.com).
* **sous-domaine hyphéné** : Remplacer le **point par un tiret** d'un sous-domaine (par exemple, www-zelster.com).
* **Nouveau TLD** : Même domaine utilisant un **nouveau TLD** (par exemple, zelster.org).
* **Homoglyphes** : Il **remplace** une lettre dans le nom de domaine par des **lettres qui se ressemblent** (par exemple, zelfser.com).
* **Transposition :** Il **échange deux lettres** dans le nom de domaine (par exemple, zelsetr.com).
* **Singularisation/Pluralisation** : Ajoute ou supprime un "s" à la fin du nom de domaine (par exemple, zeltsers.com).
* **Omission** : Il **supprime une** des lettres du nom de domaine (par exemple, zelser.com).
* **Répétition :** Il **répète une** des lettres dans le nom de domaine (par exemple, zeltsser.com).
* **Remplacement** : Comme homoglyphes mais moins furtif. Il remplace une des lettres dans le nom de domaine, peut-être par une lettre proche de la lettre originale sur le clavier (par exemple, zektser.com).
* **Sous-domaine** : Introduire un **point** à l'intérieur du nom de domaine (par exemple, ze.lster.com).
* **Insertion** : Il **insère une lettre** dans le nom de domaine (par exemple, zerltser.com).
* **Point manquant** : Ajouter le TLD au nom de domaine. (par exemple, zelstercom.com)

**Outils Automatiques**

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Sites Web**

* [https://dnstwist.it/](https://dnstwist.it)
* [https://dnstwister.report/](https://dnstwister.report)
* [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Il y a une **possibilité qu'un des bits stockés ou en communication puisse être automatiquement inversé** en raison de divers facteurs comme des éruptions solaires, des rayons cosmiques ou des erreurs matérielles.

Lorsque ce concept est **appliqué aux requêtes DNS**, il est possible que le **domaine reçu par le serveur DNS** ne soit pas le même que le domaine initialement demandé.

Par exemple, une seule modification de bit dans le domaine "windows.com" peut le changer en "windnws.com".

Les attaquants peuvent **profiter de cela en enregistrant plusieurs domaines à inversion de bits** qui sont similaires au domaine de la victime. Leur intention est de rediriger les utilisateurs légitimes vers leur propre infrastructure.

Pour plus d'informations, lisez [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Acheter un domaine de confiance

Vous pouvez rechercher sur [https://www.expireddomains.net/](https://www.expireddomains.net) un domaine expiré que vous pourriez utiliser.\
Pour vous assurer que le domaine expiré que vous allez acheter **a déjà un bon SEO**, vous pouvez vérifier comment il est catégorisé dans :

* [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
* [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Découverte d'Emails

* [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% gratuit)
* [https://phonebook.cz/](https://phonebook.cz) (100% gratuit)
* [https://maildb.io/](https://maildb.io)
* [https://hunter.io/](https://hunter.io)
* [https://anymailfinder.com/](https://anymailfinder.com)

Pour **découvrir plus** d'adresses email valides ou **vérifier celles** que vous avez déjà découvertes, vous pouvez vérifier si vous pouvez forcer les serveurs smtp de la victime. [Apprenez à vérifier/découvrir une adresse email ici](../../network-services-pentesting/pentesting-smtp/#username-bruteforce-enumeration).\
De plus, n'oubliez pas que si les utilisateurs utilisent **un portail web pour accéder à leurs mails**, vous pouvez vérifier s'il est vulnérable à **la force brute sur le nom d'utilisateur**, et exploiter la vulnérabilité si possible.

## Configuration de GoPhish

### Installation

Vous pouvez le télécharger depuis [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Téléchargez-le et décompressez-le dans `/opt/gophish` et exécutez `/opt/gophish/gophish`\
Un mot de passe pour l'utilisateur admin sera donné sur le port 3333 dans la sortie. Par conséquent, accédez à ce port et utilisez ces identifiants pour changer le mot de passe admin. Vous devrez peut-être faire un tunnel de ce port vers local :
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configuration

**Configuration du certificat TLS**

Avant cette étape, vous devriez **déjà avoir acheté le domaine** que vous allez utiliser et il doit **pointer** vers l'**IP du VPS** où vous configurez **gophish**.
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
**Configuration du mail**

Commencez par installer : `apt-get install postfix`

Ensuite, ajoutez le domaine aux fichiers suivants :

* **/etc/postfix/virtual\_domains**
* **/etc/postfix/transport**
* **/etc/postfix/virtual\_regexp**

**Changez également les valeurs des variables suivantes dans /etc/postfix/main.cf**

`myhostname = <domaine>`\
`mydestination = $myhostname, <domaine>, localhost.com, localhost`

Enfin, modifiez les fichiers **`/etc/hostname`** et **`/etc/mailname`** avec votre nom de domaine et **redémarrez votre VPS.**

Maintenant, créez un **enregistrement DNS A** de `mail.<domaine>` pointant vers l'**adresse IP** du VPS et un **enregistrement DNS MX** pointant vers `mail.<domaine>`

Maintenant, testons l'envoi d'un email :
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

Afin de créer le service gophish pour qu'il puisse être démarré automatiquement et géré en tant que service, vous pouvez créer le fichier `/etc/init.d/gophish` avec le contenu suivant :
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
Terminez de configurer le service et vérifiez-le en faisant :
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
## Configurer le serveur de messagerie et le domaine

### Attendre & être légitime

Plus un domaine est ancien, moins il est probable qu'il soit considéré comme du spam. Vous devriez donc attendre le plus longtemps possible (au moins 1 semaine) avant l'évaluation de phishing. De plus, si vous mettez une page sur un secteur de réputation, la réputation obtenue sera meilleure.

Notez que même si vous devez attendre une semaine, vous pouvez terminer la configuration de tout maintenant.

### Configurer l'enregistrement DNS inverse (rDNS)

Définissez un enregistrement rDNS (PTR) qui résout l'adresse IP du VPS au nom de domaine.

### Enregistrement Sender Policy Framework (SPF)

Vous devez **configurer un enregistrement SPF pour le nouveau domaine**. Si vous ne savez pas ce qu'est un enregistrement SPF [**lisez cette page**](../../network-services-pentesting/pentesting-smtp/#spf).

Vous pouvez utiliser [https://www.spfwizard.net/](https://www.spfwizard.net) pour générer votre politique SPF (utilisez l'IP de la machine VPS)

![](<../../.gitbook/assets/image (1037).png>)

Voici le contenu qui doit être défini à l'intérieur d'un enregistrement TXT dans le domaine :
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Enregistrement DMARC (Domain-based Message Authentication, Reporting & Conformance)

Vous devez **configurer un enregistrement DMARC pour le nouveau domaine**. Si vous ne savez pas ce qu'est un enregistrement DMARC [**lisez cette page**](../../network-services-pentesting/pentesting-smtp/#dmarc).

Vous devez créer un nouvel enregistrement DNS TXT pointant vers le nom d'hôte `_dmarc.<domain>` avec le contenu suivant :
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Vous devez **configurer un DKIM pour le nouveau domaine**. Si vous ne savez pas ce qu'est un enregistrement DMARC [**lisez cette page**](../../network-services-pentesting/pentesting-smtp/#dkim).

Ce tutoriel est basé sur : [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

{% hint style="info" %}
Vous devez concaténer les deux valeurs B64 que la clé DKIM génère :
```
v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
```
{% endhint %}

### Testez votre score de configuration d'email

Vous pouvez le faire en utilisant [https://www.mail-tester.com/](https://www.mail-tester.com)\
Il vous suffit d'accéder à la page et d'envoyer un email à l'adresse qu'ils vous donnent :
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Vous pouvez également **vérifier votre configuration email** en envoyant un email à `check-auth@verifier.port25.com` et **en lisant la réponse** (pour cela, vous devrez **ouvrir** le port **25** et voir la réponse dans le fichier _/var/mail/root_ si vous envoyez l'email en tant que root).\
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
Vous pouvez également envoyer **un message à un Gmail sous votre contrôle**, et vérifier les **en-têtes de l'email** dans votre boîte de réception Gmail, `dkim=pass` devrait être présent dans le champ d'en-tête `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Suppression de la liste noire de Spamhouse

La page [www.mail-tester.com](https://www.mail-tester.com) peut vous indiquer si votre domaine est bloqué par Spamhouse. Vous pouvez demander la suppression de votre domaine/IP à : ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Suppression de la liste noire de Microsoft

​​Vous pouvez demander la suppression de votre domaine/IP à [https://sender.office.com/](https://sender.office.com).

## Créer et lancer une campagne GoPhish

### Profil d'envoi

* Définissez un **nom pour identifier** le profil d'expéditeur
* Décidez de quel compte vous allez envoyer les emails de phishing. Suggestions : _noreply, support, servicedesk, salesforce..._
* Vous pouvez laisser le nom d'utilisateur et le mot de passe vides, mais assurez-vous de cocher l'option Ignorer les erreurs de certificat

![](<../../.gitbook/assets/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

{% hint style="info" %}
Il est recommandé d'utiliser la fonctionnalité "**Envoyer un email de test**" pour vérifier que tout fonctionne.\
Je vous recommande d'**envoyer les emails de test à des adresses 10min** afin d'éviter d'être mis sur liste noire lors des tests.
{% endhint %}

### Modèle d'email

* Définissez un **nom pour identifier** le modèle
* Ensuite, écrivez un **sujet** (rien d'étrange, juste quelque chose que vous pourriez vous attendre à lire dans un email régulier)
* Assurez-vous d'avoir coché "**Ajouter une image de suivi**"
* Rédigez le **modèle d'email** (vous pouvez utiliser des variables comme dans l'exemple suivant) :
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
Notez que **pour augmenter la crédibilité de l'email**, il est recommandé d'utiliser une signature d'un email du client. Suggestions :

* Envoyez un email à une **adresse inexistante** et vérifiez si la réponse contient une signature.
* Recherchez des **emails publics** comme info@ex.com ou press@ex.com ou public@ex.com et envoyez-leur un email et attendez la réponse.
* Essayez de contacter **un email valide découvert** et attendez la réponse.

![](<../../.gitbook/assets/image (80).png>)

{% hint style="info" %}
Le modèle d'email permet également de **joindre des fichiers à envoyer**. Si vous souhaitez également voler des défis NTLM en utilisant des fichiers/documents spécialement conçus [lisez cette page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).
{% endhint %}

### Page de destination

* Écrivez un **nom**
* **Écrivez le code HTML** de la page web. Notez que vous pouvez **importer** des pages web.
* Cochez **Capturer les données soumises** et **Capturer les mots de passe**
* Définissez une **redirection**

![](<../../.gitbook/assets/image (826).png>)

{% hint style="info" %}
En général, vous devrez modifier le code HTML de la page et faire quelques tests en local (peut-être en utilisant un serveur Apache) **jusqu'à ce que vous soyez satisfait des résultats.** Ensuite, écrivez ce code HTML dans la boîte.\
Notez que si vous avez besoin d'**utiliser des ressources statiques** pour le HTML (peut-être des pages CSS et JS), vous pouvez les enregistrer dans _**/opt/gophish/static/endpoint**_ et ensuite y accéder depuis _**/static/\<filename>**_
{% endhint %}

{% hint style="info" %}
Pour la redirection, vous pourriez **rediriger les utilisateurs vers la véritable page web principale** de la victime, ou les rediriger vers _/static/migration.html_ par exemple, mettre une **roue tournante** ([**https://loading.io/**](https://loading.io)**) pendant 5 secondes et ensuite indiquer que le processus a été réussi**.
{% endhint %}

### Utilisateurs & Groupes

* Définissez un nom
* **Importez les données** (notez que pour utiliser le modèle pour l'exemple, vous avez besoin du prénom, du nom de famille et de l'adresse email de chaque utilisateur)

![](<../../.gitbook/assets/image (163).png>)

### Campagne

Enfin, créez une campagne en sélectionnant un nom, le modèle d'email, la page de destination, l'URL, le profil d'envoi et le groupe. Notez que l'URL sera le lien envoyé aux victimes.

Notez que le **profil d'envoi permet d'envoyer un email de test pour voir à quoi ressemblera le phishing final** :

![](<../../.gitbook/assets/image (192).png>)

{% hint style="info" %}
Je vous recommande d'**envoyer les emails de test à des adresses de 10min mails** afin d'éviter d'être blacklisté lors des tests.
{% endhint %}

Une fois que tout est prêt, lancez simplement la campagne !

## Clonage de site web

Si pour une raison quelconque vous souhaitez cloner le site web, consultez la page suivante :

{% content-ref url="clone-a-website.md" %}
[clone-a-website.md](clone-a-website.md)
{% endcontent-ref %}

## Documents & Fichiers avec porte dérobée

Dans certaines évaluations de phishing (principalement pour les Red Teams), vous voudrez également **envoyer des fichiers contenant une sorte de porte dérobée** (peut-être un C2 ou peut-être juste quelque chose qui déclenchera une authentification).\
Consultez la page suivante pour quelques exemples :

{% content-ref url="phishing-documents.md" %}
[phishing-documents.md](phishing-documents.md)
{% endcontent-ref %}

## Phishing MFA

### Via Proxy MitM

L'attaque précédente est assez astucieuse car vous simulez un vrai site web et recueillez les informations fournies par l'utilisateur. Malheureusement, si l'utilisateur n'a pas saisi le bon mot de passe ou si l'application que vous avez simulée est configurée avec 2FA, **ces informations ne vous permettront pas d'usurper l'identité de l'utilisateur trompé**.

C'est là que des outils comme [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) et [**muraena**](https://github.com/muraenateam/muraena) sont utiles. Cet outil vous permettra de générer une attaque de type MitM. En gros, les attaques fonctionnent de la manière suivante :

1. Vous **usurpez le formulaire de connexion** de la vraie page web.
2. L'utilisateur **envoie** ses **identifiants** à votre page factice et l'outil envoie ceux-ci à la vraie page web, **vérifiant si les identifiants fonctionnent**.
3. Si le compte est configuré avec **2FA**, la page MitM demandera cela et une fois que l'**utilisateur l'introduit**, l'outil l'enverra à la vraie page web.
4. Une fois que l'utilisateur est authentifié, vous (en tant qu'attaquant) aurez **capturé les identifiants, le 2FA, le cookie et toute information** de chaque interaction pendant que l'outil effectue un MitM.

### Via VNC

Que se passerait-il si au lieu de **rediriger la victime vers une page malveillante** ayant le même aspect que l'originale, vous l'envoyiez vers une **session VNC avec un navigateur connecté à la vraie page web** ? Vous pourrez voir ce qu'il fait, voler le mot de passe, le MFA utilisé, les cookies...\
Vous pouvez faire cela avec [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Détecter la détection

Évidemment, l'un des meilleurs moyens de savoir si vous avez été démasqué est de **chercher votre domaine dans des listes noires**. S'il apparaît, d'une manière ou d'une autre, votre domaine a été détecté comme suspect.\
Un moyen facile de vérifier si votre domaine apparaît dans une liste noire est d'utiliser [https://malwareworld.com/](https://malwareworld.com)

Cependant, il existe d'autres moyens de savoir si la victime **cherche activement des activités de phishing suspectes dans la nature**, comme expliqué dans :

{% content-ref url="detecting-phising.md" %}
[detecting-phising.md](detecting-phising.md)
{% endcontent-ref %}

Vous pouvez **acheter un domaine avec un nom très similaire** à celui du domaine de la victime **et/ou générer un certificat** pour un **sous-domaine** d'un domaine contrôlé par vous **contenant** le **mot-clé** du domaine de la victime. Si la **victime** effectue une sorte d'**interaction DNS ou HTTP** avec eux, vous saurez qu'**il cherche activement** des domaines suspects et vous devrez être très discret.

### Évaluer le phishing

Utilisez [**Phishious** ](https://github.com/Rices/Phishious) pour évaluer si votre email va finir dans le dossier spam ou s'il va être bloqué ou réussi.

## Références

* [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
* [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
* [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
* [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
{% endhint %}
