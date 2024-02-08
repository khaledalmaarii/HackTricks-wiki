# Méthodologie Active Directory

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## Aperçu de base

**Active Directory** sert de technologie fondamentale, permettant aux **administrateurs réseau** de créer et de gérer efficacement des **domaines**, des **utilisateurs** et des **objets** au sein d'un réseau. Il est conçu pour être évolutif, facilitant l'organisation d'un grand nombre d'utilisateurs en groupes et sous-groupes gérables, tout en contrôlant les **droits d'accès** à différents niveaux.

La structure de **Active Directory** est composée de trois couches principales : **domaines**, **arbres** et **forêts**. Un **domaine** englobe une collection d'objets, tels que des **utilisateurs** ou des **appareils**, partageant une base de données commune. Les **arbres** sont des groupes de ces domaines liés par une structure commune, et une **forêt** représente la collection de plusieurs arbres, interconnectés par des **relations de confiance**, formant la couche supérieure de la structure organisationnelle. Des **droits d'accès** et de **communication spécifiques** peuvent être désignés à chacun de ces niveaux.

Les concepts clés au sein de **Active Directory** incluent :

1. **Répertoire** – Contient toutes les informations relatives aux objets Active Directory.
2. **Objet** – Désigne les entités dans le répertoire, y compris les **utilisateurs**, les **groupes** ou les **dossiers partagés**.
3. **Domaine** – Sert de conteneur pour les objets du répertoire, avec la capacité pour plusieurs domaines de coexister au sein d'une **forêt**, chacun maintenant sa propre collection d'objets.
4. **Arbre** – Un regroupement de domaines partageant un domaine racine commun.
5. **Forêt** – Le sommet de la structure organisationnelle dans Active Directory, composé de plusieurs arbres avec des **relations de confiance** entre eux.

**Services de domaine Active Directory (AD DS)** englobe une gamme de services essentiels pour la gestion centralisée et la communication au sein d'un réseau. Ces services comprennent :

1. **Services de domaine** – Centralise le stockage des données et gère les interactions entre les **utilisateurs** et les **domaines**, y compris les fonctionnalités d'**authentification** et de **recherche**.
2. **Services de certificats** – Supervise la création, la distribution et la gestion de **certificats numériques** sécurisés.
3. **Services de répertoire léger** – Prend en charge les applications activées par le répertoire via le protocole **LDAP**.
4. **Services de fédération de répertoires** – Fournit des capacités de **connexion unique** pour authentifier les utilisateurs sur plusieurs applications web en une seule session.
5. **Gestion des droits** – Aide à protéger le matériel protégé par des droits d'auteur en régulant sa distribution et son utilisation non autorisée.
6. **Service DNS** – Crucial pour la résolution des **noms de domaine**.

Pour une explication plus détaillée, consultez : [**TechTerms - Définition d'Active Directory**](https://techterms.com/definition/active_directory)


### **Authentification Kerberos**

Pour apprendre à **attaquer un AD**, vous devez **comprendre** très bien le processus d'**authentification Kerberos**.\
[**Lisez cette page si vous ne savez toujours pas comment cela fonctionne.**](kerberos-authentication.md)

## Feuille de triche

Vous pouvez consulter [https://wadcoms.github.io/](https://wadcoms.github.io) pour avoir un aperçu rapide des commandes que vous pouvez exécuter pour énumérer/exploiter un AD.

## Reconnaissance Active Directory (Pas de crédits/sessions)

Si vous avez simplement accès à un environnement AD mais que vous n'avez pas de crédentiels/sessions, vous pourriez :

* **Tester le réseau :**
* Scanner le réseau, trouver des machines et des ports ouverts et essayer d'**exploiter des vulnérabilités** ou d'**extraire des identifiants** d'entre eux (par exemple, [les imprimantes pourraient être des cibles très intéressantes](ad-information-in-printers.md).
* L'énumération du DNS pourrait fournir des informations sur les serveurs clés dans le domaine tels que web, imprimantes, partages, vpn, médias, etc.
* `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
* Consultez la [**Méthodologie générale de test d'intrusion**](../../generic-methodologies-and-resources/pentesting-methodology.md) pour plus d'informations sur la façon de procéder.
* **Vérifier l'accès nul et invité sur les services smb** (cela ne fonctionnera pas sur les versions récentes de Windows) :
* `enum4linux -a -u "" -p "" <IP du DC> && enum4linux -a -u "guest" -p "" <IP du DC>`
* `smbmap -u "" -p "" -P 445 -H <IP du DC> && smbmap -u "guest" -p "" -P 445 -H <IP du DC>`
* `smbclient -U '%' -L //<IP du DC> && smbclient -U 'guest%' -L //`
* Un guide plus détaillé sur la manière d'énumérer un serveur SMB peut être trouvé ici :

{% content-ref url="../../network-services-pentesting/pentesting-smb.md" %}
[pentesting-smb.md](../../network-services-pentesting/pentesting-smb.md)
{% endcontent-ref %}

* **Énumérer Ldap**
* `nmap -n -sV --script "ldap* and not brute" -p 389 <IP du DC>`
* Un guide plus détaillé sur la manière d'énumérer LDAP peut être trouvé ici (prêter **une attention particulière à l'accès anonyme**) :

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

* **Polluer le réseau**
* Rassembler des identifiants en [**usurpant des services avec Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
* Accéder à l'hôte en [**abusant de l'attaque de relais**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
* Rassembler des identifiants en **exposant** [**de faux services UPnP avec evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
* [**OSINT**](https://book.hacktricks.xyz/external-recon-methodology) :
* Extraire des noms d'utilisateur/noms à partir de documents internes, des médias sociaux, des services (principalement web) à l'intérieur des environnements de domaine et également des informations disponibles publiquement.
* Si vous trouvez les noms complets des employés de l'entreprise, vous pourriez essayer différentes **conventions de nom d'utilisateur AD** ([**lire ceci**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Les conventions les plus courantes sont : _NomPrénom_, _Nom.Prénom_, _NomSur_ (3 lettres de chaque), _Nom.Sur_, _NSur_, _N.Sur_, _SurNom_, _Sur.Nom_, _SurNom_, _Sur.N_, 3 _lettres aléatoires et 3 chiffres aléatoires_ (abc123).
* Outils :
* [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
* [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Énumération des utilisateurs

* **Énumération SMB/LDAP anonyme :** Consultez les pages de [**test d'intrusion SMB**](../../network-services-pentesting/pentesting-smb.md) et [**test d'intrusion LDAP**](../../network-services-pentesting/pentesting-ldap.md).
* **Énumération Kerbrute** : Lorsqu'un **nom d'utilisateur invalide est demandé**, le serveur répondra en utilisant le code d'erreur Kerberos _KRB5KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN_, nous permettant de déterminer que le nom d'utilisateur était invalide. Les **noms d'utilisateur valides** provoqueront soit le **TGT dans une réponse AS-REP** ou l'erreur _KRB5KDC\_ERR\_PREAUTH\_REQUIRED_, indiquant que l'utilisateur doit effectuer une pré-authentification.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
```
* **Serveur OWA (Outlook Web Access)**

Si vous trouvez l'un de ces serveurs sur le réseau, vous pouvez également effectuer une **énumération des utilisateurs contre celui-ci**. Par exemple, vous pourriez utiliser l'outil [**MailSniper**](https://github.com/dafthack/MailSniper):
```bash
ipmo C:\Tools\MailSniper\MailSniper.ps1
# Get info about the domain
Invoke-DomainHarvestOWA -ExchHostname [ip]
# Enumerate valid users from a list of potential usernames
Invoke-UsernameHarvestOWA -ExchHostname [ip] -Domain [domain] -UserList .\possible-usernames.txt -OutFile valid.txt
# Password spraying
Invoke-PasswordSprayOWA -ExchHostname [ip] -UserList .\valid.txt -Password Summer2021
# Get addresses list from the compromised mail
Get-GlobalAddressList -ExchHostname [ip] -UserName [domain]\[username] -Password Summer2021 -OutFile gal.txt
```
{% hint style="warning" %}
Vous pouvez trouver des listes de noms d'utilisateur dans [**ce dépôt github**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) et celui-ci ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).

Cependant, vous devriez avoir le **nom des personnes travaillant dans l'entreprise** à partir de l'étape de reconnaissance que vous auriez dû effectuer avant cela. Avec le nom et le prénom, vous pourriez utiliser le script [**namemash.py**](https://gist.github.com/superkojiman/11076951) pour générer des noms d'utilisateur potentiels valides.
{% endhint %}

### Connaître un ou plusieurs noms d'utilisateur

D'accord, donc vous savez que vous avez déjà un nom d'utilisateur valide mais pas de mots de passe... Ensuite, essayez :

* [**ASREPRoast**](asreproast.md) : Si un utilisateur **n'a pas** l'attribut _DONT\_REQ\_PREAUTH_, vous pouvez **demander un message AS\_REP** pour cet utilisateur qui contiendra des données chiffrées par une dérivation du mot de passe de l'utilisateur.
* [**Password Spraying**](password-spraying.md) : Essayez les **mots de passe les plus courants** avec chacun des utilisateurs découverts, peut-être qu'un utilisateur utilise un mauvais mot de passe (gardez à l'esprit la politique de mot de passe !).
* Notez que vous pouvez également **attaquer les serveurs OWA** pour essayer d'accéder aux serveurs de messagerie des utilisateurs.

{% content-ref url="password-spraying.md" %}
[password-spraying.md](password-spraying.md)
{% endcontent-ref %}

### Empoisonnement LLMNR/NBT-NS

Vous pourriez être en mesure d'**obtenir** certains **hachages de défi** à craquer en **empoisonnant** certains protocoles du **réseau** :

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

### Relais NTML

Si vous avez réussi à énumérer l'annuaire actif, vous aurez **plus d'e-mails et une meilleure compréhension du réseau**. Vous pourriez être en mesure de forcer des [**attaques de relais NTML**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) pour accéder à l'environnement AD.

### Vol de crédentiels NTLM

Si vous pouvez **accéder à d'autres PC ou partages** avec l'utilisateur **null ou invité**, vous pourriez **placer des fichiers** (comme un fichier SCF) qui, s'ils sont consultés, déclencheront une authentification NTML contre vous afin que vous puissiez **voler** le **défi NTLM** à craquer :

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

## Énumération de l'Active Directory AVEC des crédentiels/session

Pour cette phase, vous devez avoir **compromis les crédentiels ou une session d'un compte de domaine valide**. Si vous avez des crédentiels valides ou un shell en tant qu'utilisateur de domaine, **sachez que les options données précédemment restent des options pour compromettre d'autres utilisateurs**.

Avant de commencer l'énumération authentifiée, vous devez savoir ce qu'est le **problème de double saut Kerberos**.

{% content-ref url="kerberos-double-hop-problem.md" %}
[kerberos-double-hop-problem.md](kerberos-double-hop-problem.md)
{% endcontent-ref %}

### Énumération

Avoir compromis un compte est une **grande étape pour commencer à compromettre l'ensemble du domaine**, car vous allez pouvoir commencer l'**énumération de l'Active Directory** :

En ce qui concerne [**ASREPRoast**](asreproast.md), vous pouvez maintenant trouver tous les utilisateurs vulnérables possibles, et en ce qui concerne [**Password Spraying**](password-spraying.md), vous pouvez obtenir une **liste de tous les noms d'utilisateur** et essayer le mot de passe du compte compromis, les mots de passe vides et de nouveaux mots de passe prometteurs.

* Vous pourriez utiliser la [**CMD pour effectuer une reconnaissance de base**](../basic-cmd-for-pentesters.md#domain-info)
* Vous pouvez également utiliser [**powershell pour la reconnaissance**](../basic-powershell-for-pentesters/) qui sera plus furtif
* Vous pouvez également [**utiliser powerview**](../basic-powershell-for-pentesters/powerview.md) pour extraire des informations plus détaillées
* Un autre outil incroyable pour la reconnaissance dans un annuaire actif est [**BloodHound**](bloodhound.md). Il n'est **pas très furtif** (selon les méthodes de collecte que vous utilisez), mais **si cela ne vous dérange pas**, vous devriez absolument essayer. Trouvez où les utilisateurs peuvent se connecter en RDP, trouvez le chemin vers d'autres groupes, etc.
* **D'autres outils d'énumération AD automatisés sont :** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
* [**Enregistrements DNS de l'AD**](ad-dns-records.md) car ils pourraient contenir des informations intéressantes.
* Un **outil avec interface graphique** que vous pouvez utiliser pour énumérer l'annuaire est **AdExplorer.exe** de la suite **SysInternal**.
* Vous pouvez également rechercher dans la base de données LDAP avec **ldapsearch** pour rechercher des crédentiels dans les champs _userPassword_ & _unixUserPassword_, ou même pour _Description_. cf. [Mot de passe dans le commentaire de l'utilisateur AD sur PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) pour d'autres méthodes.
* Si vous utilisez **Linux**, vous pourriez également énumérer le domaine en utilisant [**pywerview**](https://github.com/the-useless-one/pywerview).
* Vous pourriez également essayer des outils automatisés tels que :
* [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
* [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
*   **Extraction de tous les utilisateurs du domaine**

Il est très facile d'obtenir tous les noms d'utilisateur du domaine sous Windows (`net user /domain`, `Get-DomainUser` ou `wmic useraccount get name,sid`). Sous Linux, vous pouvez utiliser : `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ou `enum4linux -a -u "user" -p "password" <DC IP>`

> Même si cette section d'énumération semble petite, c'est la partie la plus importante de toutes. Accédez aux liens (principalement celui de cmd, powershell, powerview et BloodHound), apprenez à énumérer un domaine et pratiquez jusqu'à ce que vous vous sentiez à l'aise. Lors d'une évaluation, ce sera le moment clé pour trouver votre chemin vers DA ou décider que rien ne peut être fait.

### Kerberoast

Le Kerberoasting consiste à obtenir des **tickets TGS** utilisés par des services liés à des comptes d'utilisateurs et à craquer leur chiffrement—qui est basé sur les mots de passe des utilisateurs—**hors ligne**.

Plus d'informations à ce sujet dans :

{% content-ref url="kerberoast.md" %}
[kerberoast.md](kerberoast.md)
{% endcontent-ref %}

### Connexion à distance (RDP, SSH, FTP, Win-RM, etc)

Une fois que vous avez obtenu certains crédentiels, vous pourriez vérifier si vous avez accès à une **machine**. À cette fin, vous pourriez utiliser **CrackMapExec** pour tenter de vous connecter à plusieurs serveurs avec différents protocoles, en fonction de vos analyses de ports.

### Élévation de privilèges locale

Si vous avez compromis des crédentiels ou une session en tant qu'utilisateur de domaine régulier et que vous avez **accès** avec cet utilisateur à **n'importe quelle machine dans le domaine**, vous devriez essayer de trouver un moyen d'**élever les privilèges localement et de voler des crédentiels**. Cela est nécessaire car ce n'est qu'avec des privilèges administratifs locaux que vous pourrez **extraire les hachages d'autres utilisateurs** en mémoire (LSASS) et localement (SAM).

Il y a une page complète dans ce livre sur l'[**élévation de privilèges locale dans Windows**](../windows-local-privilege-escalation/) et une [**liste de contrôle**](../checklist-windows-privilege-escalation.md). N'oubliez pas non plus d'utiliser [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Tickets de session actuels

Il est très **improbable** que vous trouviez des **tickets** dans l'utilisateur actuel **vous donnant la permission d'accéder** à des ressources inattendues, mais vous pourriez vérifier :
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTML Relay

Si vous avez réussi à énumérer l'annuaire actif, vous aurez **plus d'emails et une meilleure compréhension du réseau**. Vous pourriez être en mesure de forcer des **attaques de relais NTML**.

### **Recherche de crédits dans les partages d'ordinateurs**

Maintenant que vous avez quelques informations d'identification de base, vous devriez vérifier si vous pouvez **trouver** des **fichiers intéressants partagés dans l'AD**. Vous pourriez le faire manuellement, mais c'est une tâche très ennuyeuse et répétitive (surtout si vous trouvez des centaines de documents à vérifier).

[**Suivez ce lien pour en savoir plus sur les outils que vous pourriez utiliser.**](../../network-services-pentesting/pentesting-smb.md#domain-shared-folders-search)

### Vol de crédits NTLM

Si vous pouvez **accéder à d'autres PC ou partages**, vous pourriez **placer des fichiers** (comme un fichier SCF) qui, s'ils sont d'une manière ou d'une autre accédés, déclencheront une **authentification NTML contre vous** afin que vous puissiez **voler** le **défi NTLM** pour le craquer :

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Cette vulnérabilité permettait à tout utilisateur authentifié de **compromettre le contrôleur de domaine**.

{% content-ref url="printnightmare.md" %}
[printnightmare.md](printnightmare.md)
{% endcontent-ref %}

## Élévation de privilèges sur Active Directory AVEC des privilèges/des sessions privilégiées

**Pour les techniques suivantes, un utilisateur de domaine régulier ne suffit pas, vous avez besoin de certains privilèges/informations d'identification spéciaux pour effectuer ces attaques.**

### Extraction de hachage

Espérons que vous avez réussi à **compromettre un compte administrateur local** en utilisant [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) y compris le relais, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalade de privilèges localement](../windows-local-privilege-escalation/).\
Ensuite, il est temps de vider tous les hachages en mémoire et localement.\
[**Lisez cette page sur les différentes façons d'obtenir les hachages.**](broken-reference/)

### Pass the Hash

**Une fois que vous avez le hachage d'un utilisateur**, vous pouvez l'utiliser pour **l'impersonner**.\
Vous devez utiliser un **outil** qui **effectuera** l'**authentification NTLM en utilisant** ce **hachage**, **ou** vous pourriez créer une nouvelle **sessionlogon** et **injecter** ce **hachage** à l'intérieur du **LSASS**, donc lorsque toute **authentification NTLM est effectuée**, ce **hachage sera utilisé**. La dernière option est ce que fait mimikatz.\
[**Lisez cette page pour plus d'informations.**](../ntlm/#pass-the-hash)

### Over Pass the Hash/Pass the Key

Cette attaque vise à **utiliser le hachage NTLM de l'utilisateur pour demander des tickets Kerberos**, comme une alternative au protocole Pass The Hash commun sur le protocole NTLM. Par conséquent, cela pourrait être particulièrement **utile dans les réseaux où le protocole NTLM est désactivé** et où seul **Kerberos est autorisé** en tant que protocole d'authentification.

{% content-ref url="over-pass-the-hash-pass-the-key.md" %}
[over-pass-the-hash-pass-the-key.md](over-pass-the-hash-pass-the-key.md)
{% endcontent-ref %}

### Pass the Ticket

Dans la méthode d'attaque **Pass The Ticket (PTT)**, les attaquants **volent un ticket d'authentification de l'utilisateur** au lieu de leur mot de passe ou de leurs valeurs de hachage. Ce ticket volé est ensuite utilisé pour **usurper l'identité de l'utilisateur**, en obtenant un accès non autorisé aux ressources et services au sein d'un réseau.

{% content-ref url="pass-the-ticket.md" %}
[pass-the-ticket.md](pass-the-ticket.md)
{% endcontent-ref %}

### Réutilisation des informations d'identification

Si vous avez le **hachage** ou le **mot de passe** d'un **administrateur local**, vous devriez essayer de **vous connecter localement** à d'autres **PC** avec cela.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
{% hint style="warning" %}
Notez que ceci est assez **bruyant** et que **LAPS** pourrait **atténuer** cela.
{% endhint %}

### Abus MSSQL & Liens de Confiance

Si un utilisateur a des privilèges pour **accéder aux instances MSSQL**, il pourrait être en mesure de l'utiliser pour **exécuter des commandes** sur l'hôte MSSQL (si exécuté en tant que SA), **voler** le **hash** NetNTLM ou même effectuer une **attaque** de **relais**.\
De plus, si une instance MSSQL est de confiance (lien de base de données) par une autre instance MSSQL. Si l'utilisateur a des privilèges sur la base de données de confiance, il pourra **utiliser la relation de confiance pour exécuter des requêtes également dans l'autre instance**. Ces liens peuvent être enchaînés et à un moment donné, l'utilisateur pourrait être en mesure de trouver une base de données mal configurée où il peut exécuter des commandes.\
**Les liens entre les bases de données fonctionnent même à travers les confiances inter-forêts.**

{% content-ref url="abusing-ad-mssql.md" %}
[abusing-ad-mssql.md](abusing-ad-mssql.md)
{% endcontent-ref %}

### Délégation Non Contrainte

Si vous trouvez un objet Ordinateur avec l'attribut [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) et que vous avez des privilèges de domaine sur l'ordinateur, vous pourrez extraire les TGT de la mémoire de tous les utilisateurs qui se connectent à l'ordinateur.\
Ainsi, si un **Administrateur de Domaine se connecte à l'ordinateur**, vous pourrez extraire son TGT et vous faire passer pour lui en utilisant [Pass the Ticket](pass-the-ticket.md).\
Grâce à la délégation contrainte, vous pourriez même **compromettre automatiquement un Serveur d'Impression** (espérons que ce soit un DC).

{% content-ref url="unconstrained-delegation.md" %}
[unconstrained-delegation.md](unconstrained-delegation.md)
{% endcontent-ref %}

### Délégation Contrainte

Si un utilisateur ou un ordinateur est autorisé pour la "Délégation Contrainte", il pourra **se faire passer pour n'importe quel utilisateur pour accéder à certains services dans un ordinateur**.\
Ensuite, si vous **compromettez le hash** de cet utilisateur/ordinateur, vous pourrez **vous faire passer pour n'importe quel utilisateur** (même les administrateurs de domaine) pour accéder à certains services.

{% content-ref url="constrained-delegation.md" %}
[constrained-delegation.md](constrained-delegation.md)
{% endcontent-ref %}

### Délégation Contrainte Basée sur les Ressources

Avoir le privilège **ÉCRITURE** sur un objet Active Directory d'un ordinateur distant permet d'obtenir l'exécution de code avec des **privilèges élevés**:

{% content-ref url="resource-based-constrained-delegation.md" %}
[resource-based-constrained-delegation.md](resource-based-constrained-delegation.md)
{% endcontent-ref %}

### Abus des ACL

L'utilisateur compromis pourrait avoir certains **privilèges intéressants sur certains objets de domaine** qui pourraient vous permettre de **vous déplacer** latéralement/**escalader** les privilèges.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Abus du service Spouleur d'Impression

Découvrir un **service Spouleur en écoute** dans le domaine peut être **abusé** pour **acquérir de nouvelles informations d'identification** et **escalader les privilèges**.

{% content-ref url="acl-persistence-abuse/" %}
[printers-spooler-service-abuse](printers-spooler-service-abuse.md)
{% endcontent-ref %}

### Abus des sessions tierces

Si **d'autres utilisateurs** **accèdent** à la **machine compromise**, il est possible de **recueillir des informations d'identification en mémoire** et même **injecter des balises dans leurs processus** pour se faire passer pour eux.\
Généralement, les utilisateurs accéderont au système via RDP, voici comment effectuer quelques attaques sur des sessions RDP tierces :

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### LAPS

**LAPS** fournit un système pour gérer le **mot de passe Administrateur local** sur les ordinateurs joints au domaine, garantissant qu'il est **aléatoire**, unique et fréquemment **modifié**. Ces mots de passe sont stockés dans Active Directory et l'accès est contrôlé par des ACL pour les utilisateurs autorisés uniquement. Avec des autorisations suffisantes pour accéder à ces mots de passe, il devient possible de pivoter vers d'autres ordinateurs.

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

### Vol de Certificats

**Rassembler des certificats** de la machine compromise pourrait être un moyen d'escalader les privilèges à l'intérieur de l'environnement :

{% content-ref url="ad-certificates/certificate-theft.md" %}
[certificate-theft.md](ad-certificates/certificate-theft.md)
{% endcontent-ref %}

### Abus des Modèles de Certificats

Si des **modèles vulnérables** sont configurés, il est possible de les abuser pour escalader les privilèges :

{% content-ref url="ad-certificates/domain-escalation.md" %}
[domain-escalation.md](ad-certificates/domain-escalation.md)
{% endcontent-ref %}

## Post-exploitation avec un compte à haut privilège

### Extraction des Informations du Domaine

Une fois que vous avez les privilèges **Administrateur de Domaine** ou même mieux **Administrateur d'Entreprise**, vous pouvez **extraire** la **base de données du domaine** : _ntds.dit_.

[**Plus d'informations sur l'attaque DCSync peuvent être trouvées ici**](dcsync.md).

[**Plus d'informations sur comment voler le NTDS.dit peuvent être trouvées ici**](broken-reference/)

### Élévation de Privilèges en tant que Persistance

Certaines des techniques discutées précédemment peuvent être utilisées pour la persistance.\
Par exemple, vous pourriez :

*   Rendre les utilisateurs vulnérables à [**Kerberoast**](kerberoast.md)

```powershell
Set-DomainObject -Identity <nom_utilisateur> -Set @{serviceprincipalname="faux/RIEN"}r
```
*   Rendre les utilisateurs vulnérables à [**ASREPRoast**](asreproast.md)

```powershell
Set-DomainObject -Identity <nom_utilisateur> -XOR @{UserAccountControl=4194304}
```
*   Accorder des privilèges [**DCSync**](./#dcsync) à un utilisateur

```powershell
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Ticket Argenté

L'attaque du **Ticket Argenté** crée un **ticket de Service de Billetterie légitime (TGS)** pour un service spécifique en utilisant le **hash NTLM** (par exemple, le **hash du compte PC**). Cette méthode est utilisée pour **accéder aux privilèges du service**.

{% content-ref url="silver-ticket.md" %}
[silver-ticket.md](silver-ticket.md)
{% endcontent-ref %}

### Ticket Doré

Une **attaque du Ticket Doré** implique qu'un attaquant obtienne l'accès au **hash NTLM du compte krbtgt** dans un environnement Active Directory (AD). Ce compte est spécial car il est utilisé pour signer tous les **Tickets de Service de Billetterie (TGTs)**, qui sont essentiels pour l'authentification au sein du réseau AD.

Une fois que l'attaquant obtient ce hash, il peut créer des **TGTs** pour n'importe quel compte qu'il choisit (attaque du Ticket Argenté).

{% content-ref url="golden-ticket.md" %}
[golden-ticket.md](golden-ticket.md)
{% endcontent-ref %}

### Ticket Diamant

Ce sont comme des tickets dorés forgés de manière à **contourner les mécanismes de détection courants des tickets dorés**.

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### **Persistance du Compte Certificats**

**Avoir des certificats d'un compte ou être capable de les demander** est un très bon moyen de pouvoir persister dans le compte des utilisateurs (même s'ils changent le mot de passe) :

{% content-ref url="ad-certificates/account-persistence.md" %}
[account-persistence.md](ad-certificates/account-persistence.md)
{% endcontent-ref %}

### **Persistance du Domaine avec Certificats**

**En utilisant des certificats, il est également possible de persister avec des privilèges élevés à l'intérieur du domaine :**

{% content-ref url="ad-certificates/domain-persistence.md" %}
[domain-persistence.md](ad-certificates/domain-persistence.md)
{% endcontent-ref %}

### Groupe AdminSDHolder

L'objet **AdminSDHolder** dans Active Directory garantit la sécurité des **groupes privilégiés** (comme les Administrateurs de Domaine et les Administrateurs d'Entreprise) en appliquant une **liste de contrôle d'accès (ACL)** standard à travers ces groupes pour empêcher les modifications non autorisées. Cependant, cette fonctionnalité peut être exploitée ; si un attaquant modifie l'ACL d'AdminSDHolder pour donner un accès complet à un utilisateur régulier, cet utilisateur obtient un contrôle étendu sur tous les groupes privilégiés. Cette mesure de sécurité, censée protéger, peut donc se retourner contre vous, permettant un accès non autorisé à moins d'être étroitement surveillée.

[**Plus d'informations sur le groupe AdminDSHolder ici.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### Informations d'Identification DSRM

À l'intérieur de chaque **Contrôleur de Domaine (DC)**, un compte **administrateur local** existe. En obtenant des droits d'administrateur sur une telle machine, le hash de l'Administrateur local peut être extrait en utilisant **mimikatz**. Ensuite, une modification du registre est nécessaire pour **activer l'utilisation de ce mot de passe**, permettant un accès distant au compte Administrateur local.

{% content-ref url="dsrm-credentials.md" %}
[dsrm-credentials.md](dsrm-credentials.md)
{% endcontent-ref %}

### Persistance des ACL

Vous pourriez **donner** des **permissions spéciales** à un **utilisateur** sur certains objets de domaine spécifiques qui permettront à l'utilisateur **d'escalader les privilèges à l'avenir**.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Descripteurs de Sécurité

Les **descripteurs de sécurité** sont utilisés pour **stocker** les **permissions** qu'un **objet** a **sur** un **objet**. Si vous pouvez simplement **apporter** un **petit changement** dans le **descripteur de sécurité** d'un objet, vous pouvez obtenir des privilèges très intéressants sur cet objet sans avoir besoin d'être membre d'un groupe privilégié.

{% content-ref url="security-descriptors.md" %}
[security-descriptors.md](security-descriptors.md)
{% endcontent-ref %}

### Clé Squelette

Modifier **LSASS** en mémoire pour établir un **mot de passe universel**, accordant l'accès à tous les comptes de domaine.

{% content-ref url="skeleton-key.md" %}
[skeleton-key.md](skeleton-key.md)
{% endcontent-ref %}

### SSP Personnalisé

[Apprenez ce qu'est un SSP (Fournisseur de Support de Sécurité) ici.](../authentication-credentials-uac-and-efs.md#security-support-provider-interface-sspi)\
Vous pouvez créer votre **propre SSP** pour **capturer** en **clair** les **informations d'identification** utilisées pour accéder à la machine.\\

{% content-ref url="custom-ssp.md" %}
[custom-ssp.md](custom-ssp.md)
{% endcontent-ref %}

### DCShadow

Il enregistre un **nouveau Contrôleur de Domaine** dans l'AD et l'utilise pour **pousser des attributs** (SIDHistory, SPNs...) sur des objets spécifiés **sans** laisser de **logs** concernant les **modifications**. Vous **avez besoin de privilèges DA** et d'être à l'intérieur du **domaine racine**.\
Notez que si vous utilisez de mauvaises données, des logs assez laids apparaîtront.

{% content-ref url="dcshadow.md" %}
[dcshadow.md](dcshadow.md)
{% endcontent-ref %}

### Persistance LAPS

Précédemment, nous avons discuté de la manière d'escalader les privilèges si vous avez **suffisamment de permissions pour lire les mots de passe LAPS**. Cependant, ces mots de passe peuvent également être utilisés pour **maintenir la persistance**.\
Consultez :

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent %}

## Élévation de Privilèges dans la Forêt - Confiances de Domaine

Microsoft considère la **Forêt** comme la limite de sécurité. Cela implique que **compromettre un seul domaine pourrait potentiellement conduire à la compromission de toute la Forêt**.

### Informations de Base

Une [**confiance de domaine**](http://technet.microsoft.com/en-us/library/cc759554\(v=ws.10\).aspx) est un mécanisme de sécurité qui permet à un utilisateur d'un **domaine** d'accéder aux ressources d'un autre **domaine**. Cela crée essentiellement un lien entre les systèmes d'authentification des deux domaines, permettant aux vérifications d'authentification de s'effectuer de manière transparente. Lorsque les domaines établissent une confiance, ils échangent et conservent des **clés spécifiques** dans leurs **Contrôleurs de Domaine (DCs)**, qui sont cruciales pour l'intégrité de la confiance.

Dans un scénario typique, si un utilisateur souhaite accéder à un service dans un **domaine de confiance**, il doit d'abord demander un ticket spécial appelé **TGT inter-domaines** à son propre DC. Ce TGT est chiffré avec une **clé partagée** sur laquelle les deux domaines ont convenu. L'utilisateur présente ensuite ce TGT au **DC du domaine de confiance** pour obtenir un ticket de service (**TGS**). Après la validation réussie du TGT inter-domaines par le DC du domaine de confiance, il délivre un TGS, accordant à l'utilisateur l'accès au service.

**Étapes**:

1. Un **ordinateur client** dans le **Domaine 1** démarre le processus en utilisant son **hash NTLM** pour demander un **Ticket Granting Ticket (TGT)** à son **Contrôleur de Domaine (DC1)**.
2. DC1 délivre un nouveau TGT si le client est authentifié avec succès.
3. Le client demande ensuite un **TGT inter-domaines** à DC1, nécessaire pour accéder aux ressources dans le **Domaine 2**.
4. Le TGT inter-domaines est chiffré avec une **clé de confiance** partagée entre DC1 et DC2 dans le cadre de la confiance bidirectionnelle des domaines.
5. Le client apporte le TGT inter-domaines au **Contrôleur de Domaine du Domaine 2 (DC2)**.
6. DC2 vérifie le TGT inter-domaines en utilisant sa clé de confiance partagée et, s'il est valide, délivre un **Ticket Granting Service (TGS)** pour le serveur dans le Domaine 2 que le client souhaite accéder.
7. Enfin, le client présente ce TGS au serveur, qui est chiffré avec le hash du compte du serveur, pour accéder au service dans le Domaine 2.

### Différentes confiances

Il est important de noter qu'**une confiance peut être à sens unique ou à double sens**. Dans les options à double sens, les deux domaines se font confiance mutuellement, mais dans la relation de confiance à **sens unique**, l'un des domaines sera le domaine de confiance et l'autre le domaine de confiance. Dans ce dernier cas, **vous ne pourrez accéder qu'aux ressources à l'intérieur du domaine de confiance depuis le domaine de confiance**.

Si le Domaine A fait confiance au Domaine B, A est le domaine de confiance et B est le domaine de confiance. De plus, dans **Domaine A**, il s'agirait d'une **confiance sortante** ; et
```
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```
{% hint style="warning" %}
Il y a **2 clés de confiance**, une pour _Enfant --> Parent_ et une autre pour _Parent_ --> _Enfant_.\
Vous pouvez vérifier celle utilisée par le domaine actuel avec :
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
```
{% endhint %}

#### Injection de l'historique SID

Escaladez en tant qu'administrateur d'entreprise vers le domaine enfant/parent en abusant de la confiance avec l'injection de l'historique SID :

{% content-ref url="sid-history-injection.md" %}
[sid-history-injection.md](sid-history-injection.md)
{% endcontent-ref %}

#### Exploiter la Configuration NC inscriptible

Comprendre comment la Configuration Naming Context (NC) peut être exploitée est crucial. La Configuration NC sert de référentiel central pour les données de configuration à travers une forêt dans les environnements Active Directory (AD). Ces données sont répliquées sur chaque contrôleur de domaine (DC) au sein de la forêt, les DC inscriptibles maintenant une copie inscriptible de la Configuration NC. Pour exploiter cela, il faut avoir les **privilèges SYSTEM sur un DC**, de préférence un DC enfant.

**Lier une GPO au site du DC racine**

Le conteneur Sites de la Configuration NC inclut des informations sur tous les sites des ordinateurs joints au domaine dans la forêt AD. En opérant avec les privilèges SYSTEM sur n'importe quel DC, les attaquants peuvent lier des GPOs aux sites du DC racine. Cette action compromet potentiellement le domaine racine en manipulant les politiques appliquées à ces sites.

Pour des informations approfondies, on peut explorer la recherche sur [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromettre n'importe quelle gMSA dans la forêt**

Un vecteur d'attaque implique de cibler des gMSAs privilégiés dans le domaine. La clé racine KDS, essentielle pour calculer les mots de passe des gMSAs, est stockée dans la Configuration NC. Avec les privilèges SYSTEM sur n'importe quel DC, il est possible d'accéder à la clé racine KDS et de calculer les mots de passe pour n'importe quelle gMSA à travers la forêt.

Une analyse détaillée peut être trouvée dans la discussion sur [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Attaque de modification de schéma**

Cette méthode nécessite de la patience, en attendant la création de nouveaux objets AD privilégiés. Avec les privilèges SYSTEM, un attaquant peut modifier le schéma AD pour accorder à n'importe quel utilisateur un contrôle complet sur toutes les classes. Cela pourrait entraîner un accès non autorisé et un contrôle sur les nouveaux objets AD créés.

Des lectures supplémentaires sont disponibles sur [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**De DA à EA avec ADCS ESC5**

La vulnérabilité ADCS ESC5 vise le contrôle sur les objets d'Infrastructure à clé publique (PKI) pour créer un modèle de certificat qui permet l'authentification en tant qu'utilisateur dans la forêt. Comme les objets PKI résident dans la Configuration NC, compromettre un DC enfant inscriptible permet l'exécution d'attaques ESC5.

Plus de détails sur cela peuvent être lus dans [De DA à EA avec ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). Dans les scénarios sans ADCS, l'attaquant a la capacité de mettre en place les composants nécessaires, comme discuté dans [Escalade des administrateurs de domaine enfant vers les administrateurs d'entreprise](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### Domaine forestier externe - Unidirectionnel (entrant) ou bidirectionnel
```powershell
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM
```
Dans ce scénario, **votre domaine est de confiance** par un domaine externe vous donnant des **permissions indéterminées** dessus. Vous devrez trouver **quels principaux de votre domaine ont quel accès sur le domaine externe** puis essayer de l'exploiter :

{% content-ref url="external-forest-domain-oneway-inbound.md" %}
[external-forest-domain-oneway-inbound.md](external-forest-domain-oneway-inbound.md)
{% endcontent-ref %}

### Domaine de la Forêt Externe - Sens Unique (Sortant)
```powershell
Get-DomainTrust -Domain current.local

SourceName      : current.local   --> Current domain
TargetName      : external.local  --> Destination domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound        --> Outbound trust
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM
```
Dans ce scénario **votre domaine** fait **confiance** à certains **privilèges** à un principal d'un **domaine différent**.

Cependant, lorsqu'un **domaine est de confiance** par le domaine faisant confiance, le domaine de confiance **crée un utilisateur** avec un **nom prévisible** qui utilise comme **mot de passe le mot de passe de confiance**. Cela signifie qu'il est possible d'**accéder à un utilisateur du domaine de confiance pour pénétrer dans le domaine de confiance** pour l'énumérer et essayer d'escalader davantage de privilèges :

{% content-ref url="external-forest-domain-one-way-outbound.md" %}
[external-forest-domain-one-way-outbound.md](external-forest-domain-one-way-outbound.md)
{% endcontent-ref %}

Une autre façon de compromettre le domaine de confiance est de trouver un [**lien de confiance SQL**](abusing-ad-mssql.md#mssql-trusted-links) créé dans le **sens opposé** de la confiance du domaine (ce qui n'est pas très courant).

Une autre façon de compromettre le domaine de confiance est d'attendre dans une machine où un **utilisateur du domaine de confiance peut accéder** pour se connecter via **RDP**. Ensuite, l'attaquant pourrait injecter du code dans le processus de session RDP et **accéder au domaine d'origine de la victime** à partir de là.\
De plus, si la **victime a monté son disque dur**, à partir du processus de session RDP l'attaquant pourrait stocker des **backdoors** dans le **dossier de démarrage du disque dur**. Cette technique est appelée **RDPInception.**

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### Atténuation de l'abus de confiance de domaine

### **Filtrage SID :**

- Le risque d'attaques exploitant l'attribut d'historique SID à travers les confiances de forêt est atténué par le Filtrage SID, qui est activé par défaut sur toutes les confiances inter-forêts. Cela repose sur l'hypothèse que les confiances intra-forêts sont sécurisées, en considérant la forêt, plutôt que le domaine, comme la frontière de sécurité selon la position de Microsoft.
- Cependant, il y a un hic : le filtrage SID pourrait perturber les applications et l'accès des utilisateurs, conduisant à sa désactivation occasionnelle.

### **Authentification sélective :**

- Pour les confiances inter-forêts, l'utilisation de l'Authentification Sélective garantit que les utilisateurs des deux forêts ne sont pas automatiquement authentifiés. Au lieu de cela, des autorisations explicites sont nécessaires pour que les utilisateurs puissent accéder aux domaines et serveurs dans le domaine ou la forêt de confiance.
- Il est important de noter que ces mesures ne protègent pas contre l'exploitation du Contexte de Nom de Configuration (NC) inscriptible ou contre les attaques sur le compte de confiance.

[**Plus d'informations sur les confiances de domaine sur ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD

{% embed url="https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-lateral-movements/azure-ad-connect-hybrid-identity" %}

## Quelques défenses générales

[**Apprenez-en plus sur la protection des informations d'identification ici.**](../stealing-credentials/credentials-protections.md)\

### **Mesures de défense pour la protection des informations d'identification**

- **Restrictions des administrateurs de domaine** : Il est recommandé que les administrateurs de domaine ne soient autorisés à se connecter qu'aux contrôleurs de domaine, évitant ainsi leur utilisation sur d'autres hôtes.
- **Privilèges de compte de service** : Les services ne doivent pas être exécutés avec des privilèges d'administrateur de domaine (DA) pour maintenir la sécurité.
- **Limitation temporelle des privilèges** : Pour les tâches nécessitant des privilèges DA, leur durée doit être limitée. Cela peut être réalisé par : `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Mise en œuvre de techniques de tromperie**

- La mise en œuvre de la tromperie implique la mise en place de pièges, comme des utilisateurs ou des ordinateurs leurres, avec des fonctionnalités telles que des mots de passe qui n'expirent pas ou sont marqués comme Fiables pour la Délégation. Une approche détaillée consiste à créer des utilisateurs avec des droits spécifiques ou à les ajouter à des groupes à haut privilège.
- Un exemple pratique implique l'utilisation d'outils comme : `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Plus d'informations sur le déploiement de techniques de tromperie peuvent être trouvées sur [Deploy-Deception sur GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identification de la tromperie**

- **Pour les objets utilisateur** : Les indicateurs suspects incluent l'ObjectSID atypique, les connexions peu fréquentes, les dates de création et les faibles comptes de mots de passe incorrects.
- **Indicateurs généraux** : Comparer les attributs des objets leurres potentiels avec ceux des objets authentiques peut révéler des incohérences. Des outils comme [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) peuvent aider à identifier de telles tromperies.

### **Contournement des systèmes de détection**

- **Contournement de la détection Microsoft ATA** :
- **Énumération des utilisateurs** : Éviter l'énumération de session sur les contrôleurs de domaine pour éviter la détection ATA.
- **Impersonation de ticket** : L'utilisation de clés **aes** pour la création de tickets aide à éviter la détection en ne rétrogradant pas vers NTLM.
- **Attaques DCSync** : Il est conseillé d'exécuter à partir d'un non-contrôleur de domaine pour éviter la détection ATA, car une exécution directe à partir d'un contrôleur de domaine déclenchera des alertes.


## Références

* [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
* [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF** Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez** 💬 le [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
