```markdown
# Méthodologie Active Directory

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou souhaitez-vous accéder à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs exclusifs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de hacking en soumettant des PR au** [**dépôt hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**dépôt hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Vue d'ensemble basique

Active Directory permet aux administrateurs réseau de créer et de gérer des domaines, des utilisateurs et des objets au sein d'un réseau. Par exemple, un administrateur peut créer un groupe d'utilisateurs et leur donner des privilèges d'accès spécifiques à certains répertoires sur le serveur. À mesure qu'un réseau se développe, Active Directory offre un moyen d'organiser un grand nombre d'utilisateurs en groupes et sous-groupes logiques, tout en fournissant un contrôle d'accès à chaque niveau.

La structure d'Active Directory comprend trois niveaux principaux : 1) domaines, 2) arbres et 3) forêts. Plusieurs objets (utilisateurs ou appareils) utilisant la même base de données peuvent être regroupés dans un seul domaine. Plusieurs domaines peuvent être combinés en un seul groupe appelé un arbre. Plusieurs arbres peuvent être regroupés dans une collection appelée une forêt. Chacun de ces niveaux peut se voir attribuer des droits d'accès spécifiques et des privilèges de communication.

Concepts principaux d'un Active Directory :

1. **Annuaire** – Contient toutes les informations sur les objets de l'Active Directory
2. **Objet** – Un objet fait référence à presque tout à l'intérieur de l'annuaire (un utilisateur, un groupe, un dossier partagé...)
3. **Domaine** – Les objets de l'annuaire sont contenus à l'intérieur du domaine. À l'intérieur d'une "forêt", plusieurs domaines peuvent exister et chacun d'eux aura sa propre collection d'objets.
4. **Arbre** – Groupe de domaines ayant la même racine. Exemple : _dom.local, email.dom.local, www.dom.local_
5. **Forêt** – La forêt est le niveau le plus élevé de la hiérarchie organisationnelle et est composée d'un groupe d'arbres. Les arbres sont connectés par des relations de confiance.

Active Directory fournit plusieurs services différents, qui relèvent de la catégorie "Services de domaine Active Directory" ou AD DS. Ces services comprennent :

1. **Services de domaine** – stocke les données centralisées et gère la communication entre les utilisateurs et les domaines ; inclut l'authentification de connexion et la fonctionnalité de recherche
2. **Services de certificats** – crée, distribue et gère les certificats sécurisés
3. **Services d'annuaire léger** – prend en charge les applications activées par annuaire en utilisant le protocole ouvert (LDAP)
4. **Services de fédération d'annuaires** – fournit une authentification unique (SSO) pour authentifier un utilisateur dans plusieurs applications web en une seule session
5. **Gestion des droits** – protège les informations soumises au droit d'auteur en empêchant l'utilisation et la distribution non autorisées de contenu numérique
6. **Service DNS** – Utilisé pour résoudre les noms de domaine.

AD DS est inclus avec Windows Server (y compris Windows Server 10) et est conçu pour gérer les systèmes clients. Bien que les systèmes exécutant la version régulière de Windows ne disposent pas des fonctionnalités administratives d'AD DS, ils prennent en charge Active Directory. Cela signifie que tout ordinateur Windows peut se connecter à un groupe de travail Windows, à condition que l'utilisateur dispose des identifiants de connexion corrects.\
**Source :** [**https://techterms.com/definition/active\_directory**](https://techterms.com/definition/active\_directory)

### **Authentification Kerberos**

Pour apprendre à **attaquer un AD**, vous devez **comprendre** très bien le **processus d'authentification Kerberos**.\
[**Lisez cette page si vous ne savez toujours pas comment cela fonctionne.**](kerberos-authentication.md)

## Cheat Sheet

Vous pouvez jeter un œil à [https://wadcoms.github.io/](https://wadcoms.github.io) pour avoir un aperçu rapide des commandes que vous pouvez exécuter pour énumérer/exploiter un AD.

## Reconnaissance Active Directory (Sans identifiants/sessions)

Si vous avez juste accès à un environnement AD mais que vous n'avez aucun identifiant/session, vous pourriez :

* **Tester la sécurité du réseau :**
* Scanner le réseau, trouver des machines et des ports ouverts et essayer d'**exploiter des vulnérabilités** ou d'**extraire des identifiants** à partir de ceux-ci (par exemple, [les imprimantes pourraient être des cibles très intéressantes](ad-information-in-printers.md).
* L'énumération DNS pourrait donner des informations sur les serveurs clés dans le domaine tels que web, imprimantes, partages, vpn, médias, etc.
* `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
* Consultez la méthodologie de [**Pentesting Général**](../../generic-methodologies-and-resources/pentesting-methodology.md) pour trouver plus d'informations sur comment faire cela.
* **Vérifier l'accès null et invité sur les services smb** (cela ne fonctionnera pas sur les versions modernes de Windows) :
* `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
* `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
* `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
* Un guide plus détaillé sur la façon d'énumérer un serveur SMB peut être trouvé ici :

{% content-ref url="../../network-services-pentesting/pentesting-smb.md" %}
[pentesting-smb.md](../../network-services-pentesting/pentesting-smb.md)
{% endcontent-ref %}

* **Énumérer Ldap**
* `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
* Un guide plus détaillé sur la façon d'énumérer LDAP peut être trouvé ici (faites **attention particulière à l'accès anonyme**) :

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

* **Empoisonner le réseau**
* Récupérer des identifiants [**en se faisant passer pour des services avec Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
* Accéder à l'hôte en [**abusant de l'attaque par relais**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
* Récupérer des identifiants **en exposant** [**de faux services UPnP avec evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
* [**OSINT**](https://book.hacktricks.xyz/external-recon-methodology) :
* Extraire des noms d'utilisateur/noms à partir de documents internes, de médias sociaux, de services (principalement web) à l'intérieur des environnements de domaine et également des informations disponibles publiquement.
* Si vous trouvez les noms complets des employés de l'entreprise, vous pourriez essayer différentes **conventions de nom d'utilisateur AD** ([**lisez ceci**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Les conventions les plus courantes sont : _NameSurname_, _Name.Surname_, _NamSur_ (3lettres de chaque), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _lettres aléatoires et 3 chiffres aléatoires_ (abc123).
* Outils :
* [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
* [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Énumération des utilisateurs

* **Énumération SMB/LDAP anonyme :** Consultez les pages [**pentesting SMB**](../../network-services-pentesting/pentesting-smb.md) et [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
* **Énumération avec Kerbrute :** Lorsqu'un **nom d'utilisateur invalide est demandé**, le serveur répondra en utilisant le **code d'erreur Kerberos** _KRB5KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN_, nous permettant de déterminer que le nom d'utilisateur était invalide. Les **noms d'utilisateur valides** provoqueront soit le **TGT dans une réponse AS-REP** soit l'erreur _KRB5KDC\_ERR\_PREAUTH\_REQUIRED_, indiquant que l'utilisateur doit effectuer une pré-authentification.
```
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
```
* **Serveur OWA (Outlook Web Access)**

Si vous trouvez l'un de ces serveurs dans le réseau, vous pouvez également effectuer **l'énumération des utilisateurs contre celui-ci**. Par exemple, vous pourriez utiliser l'outil [**MailSniper**](https://github.com/dafthack/MailSniper) :
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
Vous pouvez trouver des listes de noms d'utilisateur dans [**ce dépôt github**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) \*\*\*\* et celui-ci ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).

Cependant, vous devriez avoir le **nom des personnes travaillant dans l'entreprise** à partir de l'étape de reconnaissance que vous auriez dû effectuer auparavant. Avec le nom et le prénom, vous pourriez utiliser le script [**namemash.py**](https://gist.github.com/superkojiman/11076951) pour générer des noms d'utilisateur potentiellement valides.
{% endhint %}

### Connaître un ou plusieurs noms d'utilisateur

Ok, donc vous savez que vous avez déjà un nom d'utilisateur valide mais pas de mots de passe... Alors essayez :

* [**ASREPRoast**](asreproast.md) : Si un utilisateur **n'a pas** l'attribut _DONT\_REQ\_PREAUTH_, vous pouvez **demander un message AS\_REP** pour cet utilisateur qui contiendra des données chiffrées par une dérivation du mot de passe de l'utilisateur.
* [**Password Spraying**](password-spraying.md) : Essayons les mots de passe **les plus courants** avec chacun des utilisateurs découverts, peut-être qu'un utilisateur utilise un mauvais mot de passe (gardez à l'esprit la politique de mot de passe !).
* Notez que vous pouvez également **sprayer les serveurs OWA** pour essayer d'accéder aux serveurs de messagerie des utilisateurs.

{% content-ref url="password-spraying.md" %}
[password-spraying.md](password-spraying.md)
{% endcontent-ref %}

### Empoisonnement LLMNR/NBT-NS

Vous pourriez être en mesure d'**obtenir** des **hashes de challenge** à craquer en **empoisonnant** certains protocoles du **réseau** :

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

### Relais NTML

Si vous avez réussi à énumérer l'Active Directory, vous aurez **plus d'emails et une meilleure compréhension du réseau**. Vous pourriez être en mesure de forcer des [**attaques de relais NTML**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) \*\*\*\* pour accéder à l'environnement AD.

### Voler les identifiants NTLM

Si vous pouvez **accéder à d'autres PC ou partages** avec l'utilisateur **null ou guest**, vous pourriez **placer des fichiers** (comme un fichier SCF) qui, s'ils sont accessibles, **déclencheront une authentification NTML contre vous** afin que vous puissiez **voler** le **challenge NTLM** pour le craquer :

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

## Énumération de l'Active Directory AVEC des identifiants/session

Pour cette phase, vous devez avoir **compromis les identifiants ou une session d'un compte de domaine valide.** Si vous avez des identifiants valides ou une shell en tant qu'utilisateur de domaine, **vous devriez vous rappeler que les options données précédemment sont toujours des options pour compromettre d'autres utilisateurs**.

Avant de commencer l'énumération authentifiée, vous devriez connaître le **problème du double saut Kerberos.**

{% content-ref url="kerberos-double-hop-problem.md" %}
[kerberos-double-hop-problem.md](kerberos-double-hop-problem.md)
{% endcontent-ref %}

### Énumération

Avoir compromis un compte est une **grande étape pour commencer à compromettre tout le domaine**, car vous allez pouvoir commencer l'**Énumération de l'Active Directory :**

Concernant [**ASREPRoast**](asreproast.md), vous pouvez maintenant trouver chaque utilisateur potentiellement vulnérable, et concernant [**Password Spraying**](password-spraying.md), vous pouvez obtenir une **liste de tous les noms d'utilisateur** et essayer le mot de passe du compte compromis, des mots de passe vides et de nouveaux mots de passe prometteurs.

* Vous pourriez utiliser le [**CMD pour effectuer une reconnaissance de base**](../basic-cmd-for-pentesters.md#domain-info)
* Vous pouvez également utiliser [**powershell pour la reconnaissance**](../basic-powershell-for-pentesters/) qui sera plus discret
* Vous pouvez aussi [**utiliser powerview**](../basic-powershell-for-pentesters/powerview.md) pour extraire des informations plus détaillées
* Un autre outil incroyable pour la reconnaissance dans un annuaire actif est [**BloodHound**](bloodhound.md). Il n'est **pas très discret** (selon les méthodes de collecte que vous utilisez), mais **si cela ne vous dérange pas**, vous devriez absolument l'essayer. Trouvez où les utilisateurs peuvent se connecter en RDP, trouvez des chemins vers d'autres groupes, etc.
* **D'autres outils automatisés d'énumération AD sont :** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
* [**Les enregistrements DNS de l'AD**](ad-dns-records.md) car ils peuvent contenir des informations intéressantes.
* Un **outil avec GUI** que vous pouvez utiliser pour énumérer l'annuaire est **AdExplorer.exe** de la suite **SysInternal**.
* Vous pouvez également rechercher dans la base de données LDAP avec **ldapsearch** pour chercher des identifiants dans les champs _userPassword_ & _unixUserPassword_, ou même pour _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) pour d'autres méthodes.
* Si vous utilisez **Linux**, vous pourriez également énumérer le domaine en utilisant [**pywerview**](https://github.com/the-useless-one/pywerview).
* Vous pourriez également essayer des outils automatisés tels que :
* [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
* [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
*   **Extraction de tous les utilisateurs du domaine**

Il est très facile d'obtenir tous les noms d'utilisateur du domaine depuis Windows (`net user /domain`, `Get-DomainUser` ou `wmic useraccount get name,sid`). Sous Linux, vous pouvez utiliser : `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ou `enum4linux -a -u "user" -p "password" <DC IP>`

> Même si cette section d'Énumération semble petite, c'est la partie la plus importante de toutes. Accédez aux liens (principalement celui du cmd, powershell, powerview et BloodHound), apprenez à énumérer un domaine et pratiquez jusqu'à ce que vous vous sentiez à l'aise. Lors d'une évaluation, ce sera le moment clé pour trouver votre chemin vers DA ou pour décider que rien ne peut être fait.

### Kerberoast

L'objectif de Kerberoasting est de récolter **des tickets TGS pour des services qui fonctionnent au nom des comptes d'utilisateurs de domaine**. Une partie de ces tickets TGS sont **chiffrés avec des clés dérivées des mots de passe des utilisateurs**. Par conséquent, leurs identifiants pourraient être **craqués hors ligne**.\
Plus à ce sujet dans :

{% content-ref url="kerberoast.md" %}
[kerberoast.md](kerberoast.md)
{% endcontent-ref %}

### Connexion à distance (RDP, SSH, FTP, Win-RM, etc)

Une fois que vous avez obtenu des identifiants, vous pourriez vérifier si vous avez accès à une **machine**. Pour cela, vous pourriez utiliser **CrackMapExec** pour tenter de vous connecter sur plusieurs serveurs avec différents protocoles, selon vos scans de ports.

### Élévation de privilèges locale

Si vous avez compromis des identifiants ou une session en tant qu'utilisateur de domaine régulier et que vous avez **accès** avec cet utilisateur à **n'importe quelle machine du domaine**, vous devriez essayer de trouver un moyen d'**élever vos privilèges localement et de chercher des identifiants**. C'est parce qu'avec des privilèges d'administrateur local seulement, vous serez en mesure de **dumper les hashes d'autres utilisateurs** en mémoire (LSASS) et localement (SAM).

Il y a une page complète dans ce livre sur [**l'élévation de privilèges locale sous Windows**](../windows-local-privilege-escalation/) et une [**checklist**](../checklist-windows-privilege-escalation.md). Aussi, n'oubliez pas d'utiliser [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Tickets de la session actuelle

Il est très **peu probable** que vous trouviez des **tickets** dans la session utilisateur actuelle **vous donnant la permission d'accéder** à des ressources inattendues, mais vous pourriez vérifier :
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTML Relay

Si vous avez réussi à énumérer l'Active Directory, vous aurez **plus d'emails et une meilleure compréhension du réseau**. Vous pourriez être capable de forcer des [**attaques de relais NTML**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### **Recherche de crédentials dans les partages d'ordinateurs**

Maintenant que vous avez des identifiants de base, vous devriez vérifier si vous pouvez **trouver** des **fichiers intéressants partagés dans l'AD**. Vous pourriez faire cela manuellement, mais c'est une tâche très ennuyeuse et répétitive (et encore plus si vous trouvez des centaines de documents à vérifier).

[**Suivez ce lien pour en savoir plus sur les outils que vous pourriez utiliser.**](../../network-services-pentesting/pentesting-smb.md#domain-shared-folders-search)

### Voler des crédentials NTLM

Si vous pouvez **accéder à d'autres PC ou partages**, vous pourriez **placer des fichiers** (comme un fichier SCF) qui, s'ils sont accessibles, **déclencheront une authentification NTML contre vous** afin que vous puissiez **voler** le **défi NTLM** pour le craquer :

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Cette vulnérabilité permettait à tout utilisateur authentifié de **compromettre le contrôleur de domaine**.

{% content-ref url="printnightmare.md" %}
[printnightmare.md](printnightmare.md)
{% endcontent-ref %}

## Élévation de privilèges sur Active Directory AVEC des identifiants/session privilégiés

**Pour les techniques suivantes, un utilisateur de domaine ordinaire n'est pas suffisant, vous avez besoin de certains privilèges/identifiants spéciaux pour réaliser ces attaques.**

### Extraction de hash

Espérons que vous avez réussi à **compromettre un compte d'administrateur local** en utilisant [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) y compris le relais, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalade de privilèges localement](../windows-local-privilege-escalation/).\
Ensuite, il est temps de récupérer tous les hash en mémoire et localement.\
[**Lisez cette page pour différentes méthodes d'obtention des hash.**](broken-reference/)

### Pass the Hash

**Une fois que vous avez le hash d'un utilisateur**, vous pouvez l'utiliser pour **l'usurper**.\
Vous devez utiliser un **outil** qui va **réaliser** l'**authentification NTLM en utilisant** ce **hash**, **ou** vous pourriez créer une nouvelle **sessionlogon** et **injecter** ce **hash** dans le **LSASS**, de sorte que lorsqu'une **authentification NTLM est réalisée**, ce **hash sera utilisé**. La dernière option est ce que fait mimikatz.\
[**Lisez cette page pour plus d'informations.**](../ntlm/#pass-the-hash)

### Over Pass the Hash/Pass the Key

Cette attaque vise à **utiliser le hash NTLM de l'utilisateur pour demander des tickets Kerberos**, comme alternative au Pass the Hash classique sur le protocole NTLM. Par conséquent, cela pourrait être particulièrement **utile dans les réseaux où le protocole NTLM est désactivé** et seulement **Kerberos est autorisé** comme protocole d'authentification.

{% content-ref url="over-pass-the-hash-pass-the-key.md" %}
[over-pass-the-hash-pass-the-key.md](over-pass-the-hash-pass-the-key.md)
{% endcontent-ref %}

### Pass the Ticket

Cette attaque est similaire à Pass the Key, mais au lieu d'utiliser des hash pour demander un ticket, le **ticket lui-même est volé** et utilisé pour s'authentifier en tant que son propriétaire.

{% content-ref url="pass-the-ticket.md" %}
[pass-the-ticket.md](pass-the-ticket.md)
{% endcontent-ref %}

### Réutilisation des identifiants

Si vous avez le **hash** ou le **mot de passe** d'un **administrateur local**, vous devriez essayer de **vous connecter localement** à d'autres **PC** avec celui-ci.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
{% hint style="warning" %}
Notez que cela est assez **bruyant** et **LAPS** pourrait l'**atténuer**.
{% endhint %}

### Abus de MSSQL & Liens de confiance

Si un utilisateur a des privilèges pour **accéder aux instances MSSQL**, il pourrait les utiliser pour **exécuter des commandes** sur l'hôte MSSQL (s'il fonctionne en tant que SA), **voler** le **hash** NetNTLM ou même effectuer une **attaque** par **relais**.\
De plus, si une instance MSSQL est approuvée (lien de base de données) par une autre instance MSSQL. Si l'utilisateur a des privilèges sur la base de données de confiance, il pourra **utiliser la relation de confiance pour exécuter des requêtes également dans l'autre instance**. Ces confiances peuvent être enchaînées et à un moment donné, l'utilisateur pourrait trouver une base de données mal configurée où il peut exécuter des commandes.\
**Les liens entre les bases de données fonctionnent même à travers les confiances de forêt.**

{% content-ref url="abusing-ad-mssql.md" %}
[abusing-ad-mssql.md](abusing-ad-mssql.md)
{% endcontent-ref %}

### Délégation non contrainte

Si vous trouvez un objet Ordinateur avec l'attribut [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) et que vous avez des privilèges de domaine sur l'ordinateur, vous pourrez extraire les TGT de la mémoire de tous les utilisateurs qui se connectent à l'ordinateur.\
Ainsi, si un **Administrateur de domaine se connecte à l'ordinateur**, vous pourrez extraire son TGT et l'usurper en utilisant [Pass the Ticket](pass-the-ticket.md).\
Grâce à la délégation contrainte, vous pourriez même **compromettre automatiquement un Serveur d'impression** (espérons que ce sera un DC).

{% content-ref url="unconstrained-delegation.md" %}
[unconstrained-delegation.md](unconstrained-delegation.md)
{% endcontent-ref %}

### Délégation contrainte

Si un utilisateur ou un ordinateur est autorisé pour la "Délégation contrainte", il pourra **usurper l'identité de n'importe quel utilisateur pour accéder à certains services sur un ordinateur**.\
Ensuite, si vous **compromettez le hash** de cet utilisateur/ordinateur, vous pourrez **usurper l'identité de n'importe quel utilisateur** (même les administrateurs de domaine) pour accéder à certains services.

{% content-ref url="constrained-delegation.md" %}
[constrained-delegation.md](constrained-delegation.md)
{% endcontent-ref %}

### Délégation contrainte basée sur les ressources

Il est possible d'obtenir l'exécution de code avec des **privilèges élevés sur un ordinateur distant si vous avez le privilège d'ÉCRITURE** sur l'objet AD de cet ordinateur.

{% content-ref url="resource-based-constrained-delegation.md" %}
[resource-based-constrained-delegation.md](resource-based-constrained-delegation.md)
{% endcontent-ref %}

### Abus des ACL

L'utilisateur compromis pourrait avoir certains **privilèges intéressants sur certains objets du domaine** qui pourraient vous permettre de vous **déplacer** latéralement/**escalader** les privilèges.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Abus du service Spooler d'impression

Si vous trouvez un **service Spool à l'écoute** dans le domaine, vous pourriez être en mesure de l'**abuser** pour **obtenir de nouvelles informations d'identification** et **escalader les privilèges**.\
[**Plus d'informations sur comment abuser des services Spooler ici.**](printers-spooler-service-abuse.md)

### Abus des sessions tierces

Si **d'autres utilisateurs** **accèdent** à la machine **compromise**, il est possible de **récupérer les informations d'identification de la mémoire** et même **d'injecter des balises dans leurs processus** pour les usurper.\
Habituellement, les utilisateurs accèdent au système via RDP, voici comment effectuer quelques attaques sur des sessions RDP tierces :

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### LAPS

**LAPS** vous permet de **gérer le mot de passe de l'Administrateur local** (qui est **randomisé**, unique et **changé régulièrement**) sur les ordinateurs joints au domaine. Ces mots de passe sont stockés de manière centralisée dans Active Directory et restreints aux utilisateurs autorisés à l'aide des ACL. Si vous avez **suffisamment de permissions pour lire ces mots de passe, vous pourriez vous déplacer vers d'autres ordinateurs**.

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

### Vol de certificats

La collecte de certificats à partir de la machine compromise pourrait être un moyen d'escalader les privilèges à l'intérieur de l'environnement :

{% content-ref url="ad-certificates/certificate-theft.md" %}
[certificate-theft.md](ad-certificates/certificate-theft.md)
{% endcontent-ref %}

### Abus des modèles de certificats

Si des modèles vulnérables sont configurés, il est possible de les abuser pour escalader les privilèges :

{% content-ref url="ad-certificates/domain-escalation.md" %}
[domain-escalation.md](ad-certificates/domain-escalation.md)
{% endcontent-ref %}

## Post-exploitation avec un compte à privilèges élevés

### Extraction des informations d'identification du domaine

Une fois que vous obtenez des privilèges **Administrateur de domaine** ou encore mieux **Administrateur d'entreprise**, vous pouvez **extraire** la **base de données du domaine** : _ntds.dit_.

[**Plus d'informations sur l'attaque DCSync peuvent être trouvées ici**](dcsync.md).

[**Plus d'informations sur comment voler le NTDS.dit peuvent être trouvées ici**](broken-reference/)

### Privesc comme persistance

Certaines des techniques discutées précédemment peuvent être utilisées pour la persistance.\
Par exemple, vous pourriez :

*   Rendre les utilisateurs vulnérables à [**Kerberoast**](kerberoast.md)

```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```
*   Rendre les utilisateurs vulnérables à [**ASREPRoast**](asreproast.md)

```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
*   Accorder des privilèges [**DCSync**](./#dcsync) à un utilisateur

```powershell
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

L'attaque Silver ticket est basée sur la **création d'un TGS valide pour un service une fois que le hash NTLM du service est possédé** (comme le **hash du compte PC**). Ainsi, il est possible d'**accéder à ce service** en forgeant un TGS personnalisé **en tant qu'utilisateur quelconque** (comme un accès privilégié à un ordinateur).

{% content-ref url="silver-ticket.md" %}
[silver-ticket.md](silver-ticket.md)
{% endcontent-ref %}

### Golden Ticket

Un **TGT valide en tant qu'utilisateur quelconque** peut être créé **en utilisant le hash NTLM du compte krbtgt AD**. L'avantage de forger un TGT au lieu d'un TGS est de pouvoir **accéder à n'importe quel service** (ou machine) dans le domaine en tant qu'utilisateur usurpé.

{% content-ref url="golden-ticket.md" %}
[golden-ticket.md](golden-ticket.md)
{% endcontent-ref %}

### Diamond Ticket

Ce sont comme des golden tickets forgés de manière à **contourner les mécanismes de détection des golden tickets communs**.

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### **Persistance de compte avec certificats**

**Avoir des certificats d'un compte ou être capable de les demander** est un très bon moyen de pouvoir persister dans le compte de l'utilisateur (même s'il change de mot de passe) :

{% content-ref url="ad-certificates/account-persistence.md" %}
[account-persistence.md](ad-certificates/account-persistence.md)
{% endcontent-ref %}

### **Persistance de domaine avec certificats**

**Utiliser des certificats est également possible pour persister avec des privilèges élevés à l'intérieur du domaine :**

{% content-ref url="ad-certificates/domain-persistence.md" %}
[domain-persistence.md](ad-certificates/domain-persistence.md)
{% endcontent-ref %}

### Groupe AdminSDHolder

La liste de contrôle d'accès (ACL) de l'objet **AdminSDHolder** est utilisée comme modèle pour **copier** les **permissions** sur **tous les "groupes protégés"** dans Active Directory et leurs membres. Les groupes protégés incluent des groupes privilégiés tels que les Administrateurs de domaine, les Administrateurs, les Administrateurs d'entreprise et les Administrateurs de schéma, les Opérateurs de sauvegarde et krbtgt.\
Par défaut, l'ACL de ce groupe est copiée dans tous les "groupes protégés". Cela est fait pour éviter des changements intentionnels ou accidentels à ces groupes critiques. Cependant, si un attaquant **modifie l'ACL** du groupe **AdminSDHolder**, par exemple, en donnant des permissions complètes à un utilisateur régulier, cet utilisateur aura des permissions complètes sur tous les groupes à l'intérieur du groupe protégé (en une heure).\
Et si quelqu'un essaie de supprimer cet utilisateur des Administrateurs de domaine (par exemple) en une heure ou moins, l'utilisateur sera de retour dans le groupe.\
[**Plus d'informations sur le groupe AdminDSHolder ici.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### Identifiants DSRM

Il y a un compte **administrateur local** dans chaque **DC**. Ayant des privilèges d'administrateur sur cette machine, vous pouvez utiliser mimikatz pour **extraire le hash de l'Administrateur local**. Ensuite, en modifiant un registre pour **activer ce mot de passe**, vous pourrez accéder à distance à cet utilisateur Administrateur local.

{% content-ref url="dsrm-credentials.md" %}
[dsrm-credentials.md](dsrm-credentials.md)
{% endcontent-ref %}

### Persistance ACL

Vous pourriez **donner** certains **privilèges spéciaux** à un **utilisateur** sur certains objets de domaine spécifiques qui permettront à l'utilisateur **d'escalader les privilèges à l'avenir**.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Descripteurs de sécurité

Les **descripteurs de sécurité** sont utilisés pour **stocker** les **permissions** qu'un **objet** a **sur** un **autre objet**. Si vous pouvez juste **faire** un **petit changement** dans le **descripteur de sécurité** d'un objet, vous pouvez obtenir des privilèges très intéressants sur cet objet sans avoir besoin d'être membre d'un groupe privilégié.

{% content-ref url="security-descriptors.md" %}
[security-descriptors.md](security-descriptors.md)
{% endcontent-ref %}

### Skeleton Key

**Modifier LSASS** en mémoire pour créer un **mot de passe maître** qui fonctionnera pour n'importe quel compte dans le domaine.

{% content-ref url="skeleton-key.md" %}
[skeleton-key.md](skeleton-key.md)
{% endcontent-ref %}

### SSP personnalisé

[Apprenez ce qu'est un SSP (Security Support Provider) ici.](../authentication-credentials-uac-and-efs.md#security-support-provider-interface-sspi)\
Vous pouvez créer votre **propre SSP** pour **capturer** en **clair** les **informations d'identification** utilisées pour accéder à la machine.\\

{% content-ref url="custom-ssp.md" %}
[custom-ssp.md](custom-ssp.md)
{% endcontent-ref %}

### DCShadow

Il enregistre un **nouveau Contrôleur de Domaine** dans l'AD et l'utilise pour **pousser des attributs** (SIDHistory, SPNs...) sur des objets spécifiés **sans** laisser de **logs** concernant les **modifications**. Vous **avez besoin de privilèges DA** et d'être dans le **domaine racine**.\
Notez que si vous utilisez des données incorrectes, des logs assez laids apparaîtront.

{% content-ref url="dcshadow.md" %}
[dcshadow.md](dcshadow.md)
{% endcontent-ref %}

### Persistance LAPS

Nous avons précédemment discuté de comment escalader les privilèges si vous avez **suffisamment de permissions pour lire les mots de passe LAPS**. Cependant, ces mots de passe peuvent également être utilisés pour **maintenir la persistance**.\
Vérifiez :

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

## Escalade de privilèges de forêt - Confiances de domaine

Microsoft considère que le **domaine n'est pas une limite de sécurité**, la **forêt est la limite de sécurité**. Cela signifie que **si vous compromettez un domaine à l'intérieur d'une forêt, vous pourriez être en mesure de compromettre toute la forêt**.

### Informations de base

À un niveau élevé, une [**confiance de domaine**](http://technet.microsoft.com/en-us/library/cc759554\(v=ws.10\).aspx) établit la capacité pour **les utilisateurs d'un domaine de s'authentifier** aux ressources ou d'agir en tant que [principal de sécurité](https://technet.microsoft.com/en-us/library/cc780957\(v=ws.10\).aspx) **dans un autre domaine**.

Essentiellement, tout ce qu'une confiance fait est de **relier les systèmes d'authentification de deux domaines** et de permettre au trafic d'authentification de circuler entre eux à travers un système de références.\
Lorsque **2 domaines se font confiance, ils échangent des clés**, ces **clés** seront **sauvegardées** dans les **DC** de **chaque domaine** (**2 clés par direction de confiance, la plus récente et la précédente**) et les clés seront la base de la confiance.

Lorsqu'un **utilisateur** tente d'**accéder** à un **service** dans le **domaine de confiance**, il demandera un **TGT inter-règne** au DC de son domaine. Le DC servira au client ce **TGT** qui serait **chiffré/signé** avec la **clé inter-règne** (la clé que les deux domaines ont **échangée**). Ensuite, le **client** **accédera** au **DC de l'autre domaine** et **demandera** un **TGS** pour le service en utilisant le **TGT inter-règne**. Le **DC** du domaine de confiance **vérifiera** la **clé** utilisée, si elle est correcte, il **fera confiance à tout dans ce ticket** et servira le TGS au client.

![](<../../.gitbook/assets/image (166) (1).png>)

### Différentes confiances

Il est important de noter qu'une **confiance peut être à sens unique ou à double sens**. Dans les options à double sens, les deux domaines se font confiance, mais dans la relation de confiance **à sens unique**, l'un des domaines sera le **domaine de confiance** et l'autre le **domaine de confiance**. Dans le dernier cas, **vous ne pourrez accéder aux ressources du domaine de confiance qu'à partir du domaine de confiance**.

Si le domaine A fait confiance au domaine B, A est le domaine de confiance et B est le domaine de confiance. De plus, dans le **domaine A**, ce serait une **confiance sortante** ; et dans le **domaine B**, ce serait une **confiance entrante**.

**Différentes relations de confiance**

* **Parent-Enfant** – partie de la même forêt – un domaine enfant conserve une confiance implicite bidirectionnelle transitive avec son parent. C'est probablement le type de confiance le plus courant que vous rencontrerez.
* **Lien croisé** – également appelé "confiance de raccourci" entre les domaines enfants pour améliorer les temps de référence. Normalement, les références dans une forêt complexe doivent remonter jusqu'à la racine de la forêt, puis red
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
Vous pouvez utiliser celle utilisée par le domaine actuel avec :
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
```
#### Injection de SID-History

Élévation en tant qu'admin Enterprise vers le domaine enfant/parent en abusant de la confiance avec l'injection de SID-History :

{% content-ref url="sid-history-injection.md" %}
[sid-history-injection.md](sid-history-injection.md)
{% endcontent-ref %}

#### Exploiter la Configuration NC modifiable

La Configuration NC est le dépôt principal pour les informations de configuration d'une forêt et est répliquée sur chaque DC de la forêt. De plus, chaque DC modifiable (pas les DC en lecture seule) dans la forêt détient une copie modifiable de la Configuration NC. Exploiter cela nécessite de s'exécuter en tant que SYSTEM sur un DC (enfant).

Il est possible de compromettre le domaine racine de diverses manières couvertes ci-dessous.

**Lier GPO au site du DC racine**

Le conteneur Sites dans la Configuration NC contient tous les sites des ordinateurs joints au domaine dans la forêt AD. Il est possible de lier des GPOs aux sites lorsqu'on s'exécute en tant que SYSTEM sur n'importe quel DC de la forêt, y compris le(s) site(s) des DCs racines de la forêt, et ainsi de compromettre ceux-ci.

Plus de détails peuvent être lus ici [Recherche sur le contournement du filtrage SID](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromettre n'importe quel gMSA dans la forêt**

L'attaque dépend des gMSAs privilégiés dans le domaine ciblé.

La clé racine KDS, qui est utilisée pour calculer le mot de passe des gMSAs dans la forêt, est stockée dans la Configuration NC. Lorsqu'on s'exécute en tant que SYSTEM sur n'importe quel DC de la forêt, on peut lire la clé racine KDS et calculer le mot de passe de n'importe quel gMSA dans la forêt.

Plus de détails peuvent être lus ici : [Attaque de confiance Golden gMSA du domaine enfant au parent](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Attaque de changement de schéma**

L'attaque nécessite que l'attaquant attende la création de nouveaux objets AD privilégiés.

Lorsqu'on s'exécute en tant que SYSTEM sur n'importe quel DC de la forêt, on peut accorder à n'importe quel utilisateur un contrôle total sur toutes les classes dans le schéma AD. Ce contrôle peut être abusé pour créer une ACE dans le descripteur de sécurité par défaut de n'importe quel objet AD qui accorde un contrôle total à un principal compromis. Toutes les nouvelles instances des types d'objets AD modifiés auront cette ACE.

Plus de détails peuvent être lus ici : [Attaque de confiance de changement de schéma du domaine enfant au parent](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**De DA à EA avec ADCS ESC5**

Les attaques ADCS ESC5 (Vulnerable PKI Object Access Control) abusent du contrôle sur les objets PKI pour créer un modèle de certificat vulnérable qui peut être abusé pour s'authentifier en tant qu'utilisateur quelconque dans la forêt. Puisque tous les objets PKI sont stockés dans la Configuration NC, on peut exécuter ESC5 si on a compromis n'importe quel DC modifiable (enfant) dans la forêt.

Plus de détails peuvent être lus ici : [De DA à EA avec ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c)

Dans le cas où la forêt AD n'a pas ADCS, l'attaquant peut créer les composants nécessaires comme décrit ici : [Escalade des admins du domaine enfant aux admins d'entreprise en 5 minutes en abusant d'AD CS, un suivi](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### Domaine de forêt externe - Unidirectionnel (entrant) ou bidirectionnel
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
Dans ce scénario, **votre domaine est approuvé** par un domaine externe vous accordant des **permissions indéterminées** sur celui-ci. Vous devrez déterminer **quels principaux de votre domaine ont quel accès sur le domaine externe** puis essayer de l'exploiter :

{% content-ref url="external-forest-domain-oneway-inbound.md" %}
[external-forest-domain-oneway-inbound.md](external-forest-domain-oneway-inbound.md)
{% endcontent-ref %}

### Domaine de forêt externe - Unidirectionnel (Sortant)
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
Dans ce scénario, **votre domaine** accorde certains **privilèges** à un principal d'un **autre domaine**.

Cependant, lorsqu'un **domaine est approuvé** par le domaine de confiance, le domaine approuvé **crée un utilisateur** avec un **nom prévisible** qui utilise comme **mot de passe le mot de passe approuvé**. Cela signifie qu'il est possible d'**accéder à un utilisateur du domaine de confiance pour entrer dans le domaine approuvé** afin de l'énumérer et d'essayer d'escalader davantage de privilèges :

{% content-ref url="external-forest-domain-one-way-outbound.md" %}
[external-forest-domain-one-way-outbound.md](external-forest-domain-one-way-outbound.md)
{% endcontent-ref %}

Une autre manière de compromettre le domaine approuvé est de trouver un [**lien SQL approuvé**](abusing-ad-mssql.md#mssql-trusted-links) créé dans la **direction opposée** de la confiance du domaine (ce qui n'est pas très courant).

Une autre manière de compromettre le domaine approuvé est d'attendre dans une machine où un **utilisateur du domaine approuvé peut accéder** pour se connecter via **RDP**. Ensuite, l'attaquant pourrait injecter du code dans le processus de session RDP et **accéder au domaine d'origine de la victime** à partir de là.\
De plus, si la **victime a monté son disque dur**, à partir du processus de **session RDP**, l'attaquant pourrait stocker des **portes dérobées** dans le **dossier de démarrage du disque dur**. Cette technique est appelée **RDPInception.**

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### Atténuation de l'abus de confiance de domaine

**Filtrage SID :**

* Éviter les attaques qui abusent de l'attribut historique SID à travers la confiance inter-forêt.
* Activé par défaut sur toutes les confiances inter-forêts. Les confiances intra-forêt sont considérées comme sécurisées par défaut (MS considère le forêt et non le domaine comme une frontière de sécurité).
* Mais, comme le filtrage SID a le potentiel de casser des applications et l'accès des utilisateurs, il est souvent désactivé.
* Authentification Sélective
* Dans une confiance inter-forêt, si l'Authentification Sélective est configurée, les utilisateurs entre les confiances ne seront pas automatiquement authentifiés. Un accès individuel aux domaines et serveurs dans le domaine/forêt de confiance devrait être donné.
* Ne prévient pas l'exploitation de NC Configration inscriptible et l'attaque de compte de confiance.

[**Plus d'informations sur les confiances de domaine sur ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Cloud & Cloud -> AD

{% embed url="https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-lateral-movements/azure-ad-connect-hybrid-identity" %}

## Quelques défenses générales

[**En savoir plus sur comment protéger les identifiants ici.**](../stealing-credentials/credentials-protections.md)\
**S'il vous plaît, trouvez certaines migrations contre chaque technique dans la description de la technique.**

* Ne pas permettre aux administrateurs de domaine de se connecter sur d'autres hôtes à part les contrôleurs de domaine
* Ne jamais exécuter un service avec des privilèges DA
* Si vous avez besoin de privilèges d'administrateur de domaine, limitez le temps : `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### Tromperie

* Le mot de passe n'expire pas
* Approuvé pour délégation
* Utilisateurs avec SPN
* Mot de passe dans la description
* Utilisateurs qui sont membres de groupes à privilèges élevés
* Utilisateurs avec des droits ACL sur d'autres utilisateurs, groupes ou conteneurs
* Objets informatiques
* ...
* [https://github.com/samratashok/Deploy-Deception](https://github.com/samratashok/Deploy-Deception)
* `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`

## Comment identifier la tromperie

**Pour les objets utilisateur :**

* ObjectSID (différent du domaine)
* lastLogon, lastlogontimestamp
* Logoncount (un très faible nombre est suspect)
* whenCreated
* Badpwdcount (un très faible nombre est suspect)

**Général :**

* Certaines solutions remplissent d'informations tous les attributs possibles. Par exemple, comparez les attributs d'un objet informatique avec l'attribut d'un objet informatique 100% réel comme DC. Ou les utilisateurs contre le RID 500 (admin par défaut).
* Vérifiez si quelque chose est trop beau pour être vrai
* [https://github.com/JavelinNetworks/HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster)

### Contournement de la détection Microsoft ATA

#### Énumération des utilisateurs

ATA ne se plaint que lorsque vous essayez d'énumérer les sessions dans le DC, donc si vous ne cherchez pas de sessions dans le DC mais dans le reste des hôtes, vous ne serez probablement pas détecté.

#### Création d'impersonation de tickets (Over pass the hash, golden ticket...)

Créez toujours les tickets en utilisant également les clés **aes** car ce que ATA identifie comme malveillant est la dégradation vers NTLM.

#### DCSync

Si vous n'exécutez pas cela à partir d'un contrôleur de domaine, ATA va vous attraper, désolé.

## Plus d'outils

* [Script Powershell pour automatiser l'audit de domaine](https://github.com/phillips321/adaudit)
* [Script Python pour énumérer active directory](https://github.com/ropnop/windapsearch)
* [Script Python pour énumérer active directory](https://github.com/CroweCybersecurity/ad-ldap-enum)

## Références

* [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version du PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**dépôt hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**dépôt hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
