# Méthodologie Active Directory

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
{% endhint %}

## Aperçu de base

**Active Directory** sert de technologie fondamentale, permettant aux **administrateurs réseau** de créer et de gérer efficacement des **domaines**, des **utilisateurs** et des **objets** au sein d'un réseau. Il est conçu pour évoluer, facilitant l'organisation d'un grand nombre d'utilisateurs en **groupes** et **sous-groupes** gérables, tout en contrôlant les **droits d'accès** à divers niveaux.

La structure de **Active Directory** se compose de trois couches principales : **domaines**, **arbres** et **forêts**. Un **domaine** englobe un ensemble d'objets, tels que des **utilisateurs** ou des **dispositifs**, partageant une base de données commune. Les **arbres** sont des groupes de ces domaines liés par une structure partagée, et une **forêt** représente la collection de plusieurs arbres, interconnectés par des **relations de confiance**, formant la couche supérieure de la structure organisationnelle. Des **droits d'accès** et de **communication** spécifiques peuvent être désignés à chacun de ces niveaux.

Les concepts clés au sein de **Active Directory** incluent :

1. **Répertoire** – Contient toutes les informations relatives aux objets Active Directory.
2. **Objet** – Désigne des entités au sein du répertoire, y compris des **utilisateurs**, des **groupes** ou des **dossiers partagés**.
3. **Domaine** – Sert de conteneur pour les objets du répertoire, avec la capacité de plusieurs domaines à coexister au sein d'une **forêt**, chacun maintenant sa propre collection d'objets.
4. **Arbre** – Un regroupement de domaines partageant un domaine racine commun.
5. **Forêt** – Le sommet de la structure organisationnelle dans Active Directory, composée de plusieurs arbres avec des **relations de confiance** entre eux.

**Active Directory Domain Services (AD DS)** englobe une gamme de services critiques pour la gestion centralisée et la communication au sein d'un réseau. Ces services comprennent :

1. **Services de domaine** – Centralise le stockage des données et gère les interactions entre **utilisateurs** et **domaines**, y compris les fonctionnalités d'**authentification** et de **recherche**.
2. **Services de certificats** – Supervise la création, la distribution et la gestion de **certificats numériques** sécurisés.
3. **Services de répertoire léger** – Prend en charge les applications activées par le répertoire via le **protocole LDAP**.
4. **Services de fédération de répertoire** – Fournit des capacités de **connexion unique** pour authentifier les utilisateurs à travers plusieurs applications web en une seule session.
5. **Gestion des droits** – Aide à protéger le matériel protégé par des droits d'auteur en régulant sa distribution et son utilisation non autorisées.
6. **Service DNS** – Crucial pour la résolution des **noms de domaine**.

Pour une explication plus détaillée, consultez : [**TechTerms - Définition d'Active Directory**](https://techterms.com/definition/active\_directory)

### **Authentification Kerberos**

Pour apprendre à **attaquer un AD**, vous devez **comprendre** très bien le **processus d'authentification Kerberos**.\
[**Lisez cette page si vous ne savez toujours pas comment cela fonctionne.**](kerberos-authentication.md)

## Fiche de triche

Vous pouvez consulter [https://wadcoms.github.io/](https://wadcoms.github.io) pour avoir un aperçu rapide des commandes que vous pouvez exécuter pour énumérer/exploiter un AD.

## Reconnaissance Active Directory (Pas de crédentiels/sessions)

Si vous avez simplement accès à un environnement AD mais que vous n'avez aucun crédentiel/session, vous pourriez :

* **Tester le réseau :**
* Scanner le réseau, trouver des machines et des ports ouverts et essayer d'**exploiter des vulnérabilités** ou d'**extraire des crédentiels** à partir d'eux (par exemple, [les imprimantes pourraient être des cibles très intéressantes](ad-information-in-printers.md)).
* L'énumération DNS pourrait donner des informations sur les serveurs clés dans le domaine tels que web, imprimantes, partages, vpn, médias, etc.
* `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
* Consultez la [**Méthodologie de Pentesting Générale**](../../generic-methodologies-and-resources/pentesting-methodology.md) pour trouver plus d'informations sur la façon de procéder.
* **Vérifiez l'accès nul et invité sur les services smb** (cela ne fonctionnera pas sur les versions modernes de Windows) :
* `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
* `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
* `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
* Un guide plus détaillé sur la façon d'énumérer un serveur SMB peut être trouvé ici :

{% content-ref url="../../network-services-pentesting/pentesting-smb/" %}
[pentesting-smb](../../network-services-pentesting/pentesting-smb/)
{% endcontent-ref %}

* **Énumérer Ldap**
* `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
* Un guide plus détaillé sur la façon d'énumérer LDAP peut être trouvé ici (prêtez **une attention particulière à l'accès anonyme**) :

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

* **Poisonner le réseau**
* Rassembler des crédentiels [**en usurpant des services avec Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
* Accéder à l'hôte en [**abusant de l'attaque par relais**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
* Rassembler des crédentiels **en exposant** [**de faux services UPnP avec evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
* [**OSINT**](https://book.hacktricks.xyz/external-recon-methodology) :
* Extraire des noms d'utilisateur/noms à partir de documents internes, de réseaux sociaux, de services (principalement web) à l'intérieur des environnements de domaine et également à partir de sources disponibles publiquement.
* Si vous trouvez les noms complets des employés de l'entreprise, vous pourriez essayer différentes **conventions de nom d'utilisateur AD** ([**lisez ceci**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Les conventions les plus courantes sont : _NomPrénom_, _Nom.Prénom_, _NomPr_ (3 lettres de chaque), _Nom.Pr_, _NPrénom_, _N.Prénom_, _PrénomNom_, _Prénom.Nom_, _PrénomN_, _Prénom.N_, 3 _lettres aléatoires et 3 chiffres aléatoires_ (abc123).
* Outils :
* [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
* [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Énumération des utilisateurs

* **Énumération SMB/LDAP anonyme :** Consultez les pages [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/) et [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
* **Énumération Kerbrute** : Lorsqu'un **nom d'utilisateur invalide est demandé**, le serveur répondra en utilisant le code d'erreur **Kerberos** _KRB5KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN_, nous permettant de déterminer que le nom d'utilisateur était invalide. Les **noms d'utilisateur valides** provoqueront soit le **TGT dans une réponse AS-REP**, soit l'erreur _KRB5KDC\_ERR\_PREAUTH\_REQUIRED_, indiquant que l'utilisateur doit effectuer une pré-authentification.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
```
* **Serveur OWA (Outlook Web Access)**

Si vous trouvez l'un de ces serveurs dans le réseau, vous pouvez également effectuer **une énumération des utilisateurs contre celui-ci**. Par exemple, vous pourriez utiliser l'outil [**MailSniper**](https://github.com/dafthack/MailSniper):
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
Vous pouvez trouver des listes de noms d'utilisateur dans [**ce dépôt github**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) \*\*\*\* et celui-ci ([**noms d'utilisateur statistiquement probables**](https://github.com/insidetrust/statistically-likely-usernames)).

Cependant, vous devriez avoir le **nom des personnes travaillant dans l'entreprise** à partir de l'étape de reconnaissance que vous avez effectuée auparavant. Avec le nom et le prénom, vous pourriez utiliser le script [**namemash.py**](https://gist.github.com/superkojiman/11076951) pour générer des noms d'utilisateur potentiellement valides.
{% endhint %}

### Connaître un ou plusieurs noms d'utilisateur

D'accord, donc vous savez que vous avez déjà un nom d'utilisateur valide mais pas de mots de passe... Alors essayez :

* [**ASREPRoast**](asreproast.md) : Si un utilisateur **n'a pas** l'attribut _DONT\_REQ\_PREAUTH_, vous pouvez **demander un message AS\_REP** pour cet utilisateur qui contiendra des données chiffrées par une dérivation du mot de passe de l'utilisateur.
* [**Password Spraying**](password-spraying.md) : Essayons les mots de passe les plus **courants** avec chacun des utilisateurs découverts, peut-être qu'un utilisateur utilise un mauvais mot de passe (gardez à l'esprit la politique de mot de passe !).
* Notez que vous pouvez également **sprayer les serveurs OWA** pour essayer d'accéder aux serveurs de messagerie des utilisateurs.

{% content-ref url="password-spraying.md" %}
[password-spraying.md](password-spraying.md)
{% endcontent-ref %}

### LLMNR/NBT-NS Poisoning

Vous pourriez être en mesure d'**obtenir** des **hashes** de challenge pour cracker en **empoisonnant** certains protocoles du **réseau** :

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

### NTML Relay

Si vous avez réussi à énumérer l'annuaire actif, vous aurez **plus d'emails et une meilleure compréhension du réseau**. Vous pourriez être en mesure de forcer des [**attaques de relais NTML**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) \*\*\*\* pour accéder à l'environnement AD.

### Voler des identifiants NTLM

Si vous pouvez **accéder à d'autres PC ou partages** avec l'**utilisateur null ou invité**, vous pourriez **placer des fichiers** (comme un fichier SCF) qui, s'ils sont accédés d'une manière ou d'une autre, **déclencheront une authentification NTML contre vous** afin que vous puissiez **voler** le **challenge NTLM** pour le cracker :

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

## Énumération de l'Active Directory AVEC des identifiants/session

Pour cette phase, vous devez avoir **compromis les identifiants ou une session d'un compte de domaine valide.** Si vous avez des identifiants valides ou un shell en tant qu'utilisateur de domaine, **vous devez vous rappeler que les options données auparavant sont toujours des options pour compromettre d'autres utilisateurs**.

Avant de commencer l'énumération authentifiée, vous devriez savoir quel est le **problème du double saut Kerberos.**

{% content-ref url="kerberos-double-hop-problem.md" %}
[kerberos-double-hop-problem.md](kerberos-double-hop-problem.md)
{% endcontent-ref %}

### Énumération

Avoir compromis un compte est un **grand pas pour commencer à compromettre tout le domaine**, car vous allez pouvoir commencer l'**énumération de l'Active Directory :**

Concernant [**ASREPRoast**](asreproast.md), vous pouvez maintenant trouver chaque utilisateur vulnérable possible, et concernant [**Password Spraying**](password-spraying.md), vous pouvez obtenir une **liste de tous les noms d'utilisateur** et essayer le mot de passe du compte compromis, des mots de passe vides et de nouveaux mots de passe prometteurs.

* Vous pourriez utiliser le [**CMD pour effectuer une reconnaissance de base**](../basic-cmd-for-pentesters.md#domain-info)
* Vous pouvez également utiliser [**powershell pour la reconnaissance**](../basic-powershell-for-pentesters/) qui sera plus discrète
* Vous pouvez aussi [**utiliser powerview**](../basic-powershell-for-pentesters/powerview.md) pour extraire des informations plus détaillées
* Un autre outil incroyable pour la reconnaissance dans un annuaire actif est [**BloodHound**](bloodhound.md). Ce n'est **pas très discret** (selon les méthodes de collecte que vous utilisez), mais **si cela ne vous dérange pas**, vous devriez absolument l'essayer. Trouvez où les utilisateurs peuvent RDP, trouvez le chemin vers d'autres groupes, etc.
* **D'autres outils d'énumération AD automatisés sont :** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
* [**Enregistrements DNS de l'AD**](ad-dns-records.md) car ils pourraient contenir des informations intéressantes.
* Un **outil avec interface graphique** que vous pouvez utiliser pour énumérer le répertoire est **AdExplorer.exe** de la **SysInternal** Suite.
* Vous pouvez également rechercher dans la base de données LDAP avec **ldapsearch** pour chercher des identifiants dans les champs _userPassword_ & _unixUserPassword_, ou même pour _Description_. cf. [Mot de passe dans le commentaire utilisateur AD sur PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) pour d'autres méthodes.
* Si vous utilisez **Linux**, vous pourriez également énumérer le domaine en utilisant [**pywerview**](https://github.com/the-useless-one/pywerview).
* Vous pourriez également essayer des outils automatisés comme :
* [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
* [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
*   **Extraction de tous les utilisateurs de domaine**

Il est très facile d'obtenir tous les noms d'utilisateur du domaine depuis Windows (`net user /domain`, `Get-DomainUser` ou `wmic useraccount get name,sid`). Sous Linux, vous pouvez utiliser : `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ou `enum4linux -a -u "user" -p "password" <DC IP>`

> Même si cette section d'énumération semble petite, c'est la partie la plus importante de toutes. Accédez aux liens (principalement celui de cmd, powershell, powerview et BloodHound), apprenez à énumérer un domaine et pratiquez jusqu'à ce que vous vous sentiez à l'aise. Lors d'une évaluation, ce sera le moment clé pour trouver votre chemin vers DA ou pour décider que rien ne peut être fait.

### Kerberoast

Kerberoasting implique d'obtenir des **tickets TGS** utilisés par des services liés à des comptes d'utilisateur et de cracker leur chiffrement—qui est basé sur les mots de passe des utilisateurs—**hors ligne**.

Plus d'informations à ce sujet dans :

{% content-ref url="kerberoast.md" %}
[kerberoast.md](kerberoast.md)
{% endcontent-ref %}

### Connexion à distance (RDP, SSH, FTP, Win-RM, etc)

Une fois que vous avez obtenu des identifiants, vous pourriez vérifier si vous avez accès à une **machine**. Pour cela, vous pourriez utiliser **CrackMapExec** pour tenter de vous connecter à plusieurs serveurs avec différents protocoles, selon vos analyses de ports.

### Escalade de privilèges locale

Si vous avez compromis des identifiants ou une session en tant qu'utilisateur de domaine régulier et que vous avez **accès** avec cet utilisateur à **n'importe quelle machine dans le domaine**, vous devriez essayer de trouver votre chemin pour **escalader les privilèges localement et chercher des identifiants**. C'est parce qu'avec des privilèges d'administrateur local, vous serez en mesure de **dump les hashes d'autres utilisateurs** en mémoire (LSASS) et localement (SAM).

Il y a une page complète dans ce livre sur [**l'escalade de privilèges locale dans Windows**](../windows-local-privilege-escalation/) et une [**checklist**](../checklist-windows-privilege-escalation.md). De plus, n'oubliez pas d'utiliser [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

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

Si vous avez réussi à énumérer l'annuaire actif, vous aurez **plus d'emails et une meilleure compréhension du réseau**. Vous pourriez être en mesure de forcer des attaques [**relay NTML**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### **Recherche de crédentiels dans les partages d'ordinateurs**

Maintenant que vous avez quelques crédentiels de base, vous devriez vérifier si vous pouvez **trouver** des **fichiers intéressants partagés dans l'AD**. Vous pourriez le faire manuellement, mais c'est une tâche très ennuyeuse et répétitive (et encore plus si vous trouvez des centaines de documents à vérifier).

[**Suivez ce lien pour en savoir plus sur les outils que vous pourriez utiliser.**](../../network-services-pentesting/pentesting-smb/#domain-shared-folders-search)

### Vol de crédentiels NTLM

Si vous pouvez **accéder à d'autres PC ou partages**, vous pourriez **placer des fichiers** (comme un fichier SCF) qui, s'ils sont accédés d'une manière ou d'une autre, **déclencheront une authentification NTML contre vous**, vous permettant ainsi de **voler** le **défi NTLM** pour le craquer :

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Cette vulnérabilité permettait à tout utilisateur authentifié de **compromettre le contrôleur de domaine**.

{% content-ref url="printnightmare.md" %}
[printnightmare.md](printnightmare.md)
{% endcontent-ref %}

## Élévation de privilèges sur Active Directory AVEC des crédentiels/sessions privilégiés

**Pour les techniques suivantes, un utilisateur de domaine régulier ne suffit pas, vous avez besoin de privilèges/crédentiels spéciaux pour effectuer ces attaques.**

### Extraction de hachages

Espérons que vous avez réussi à **compromettre un compte administrateur local** en utilisant [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) y compris le relais, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [élévation de privilèges localement](../windows-local-privilege-escalation/).\
Ensuite, il est temps de vider tous les hachages en mémoire et localement.\
[**Lisez cette page sur les différentes façons d'obtenir les hachages.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Une fois que vous avez le hachage d'un utilisateur**, vous pouvez l'utiliser pour **l'usurper**.\
Vous devez utiliser un **outil** qui **effectuera** l'**authentification NTLM en utilisant** ce **hachage**, **ou** vous pourriez créer une nouvelle **sessionlogon** et **injecter** ce **hachage** dans le **LSASS**, de sorte que lorsque toute **authentification NTLM est effectuée**, ce **hachage sera utilisé.** La dernière option est ce que fait mimikatz.\
[**Lisez cette page pour plus d'informations.**](../ntlm/#pass-the-hash)

### Over Pass the Hash/Pass the Key

Cette attaque vise à **utiliser le hachage NTLM de l'utilisateur pour demander des tickets Kerberos**, en alternative au commun Pass The Hash sur le protocole NTLM. Par conséquent, cela pourrait être particulièrement **utile dans les réseaux où le protocole NTLM est désactivé** et où seul **Kerberos est autorisé** comme protocole d'authentification.

{% content-ref url="over-pass-the-hash-pass-the-key.md" %}
[over-pass-the-hash-pass-the-key.md](over-pass-the-hash-pass-the-key.md)
{% endcontent-ref %}

### Pass the Ticket

Dans la méthode d'attaque **Pass The Ticket (PTT)**, les attaquants **volent le ticket d'authentification d'un utilisateur** au lieu de son mot de passe ou de ses valeurs de hachage. Ce ticket volé est ensuite utilisé pour **usurper l'utilisateur**, obtenant un accès non autorisé aux ressources et services au sein d'un réseau.

{% content-ref url="pass-the-ticket.md" %}
[pass-the-ticket.md](pass-the-ticket.md)
{% endcontent-ref %}

### Réutilisation des crédentiels

Si vous avez le **hachage** ou le **mot de passe** d'un **administrateur local**, vous devriez essayer de **vous connecter localement** à d'autres **PC** avec.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
{% hint style="warning" %}
Notez que cela est assez **bruyant** et que **LAPS** le **mitigera**.
{% endhint %}

### Abus de MSSQL & Liens de confiance

Si un utilisateur a des privilèges pour **accéder aux instances MSSQL**, il pourrait être en mesure de l'utiliser pour **exécuter des commandes** sur l'hôte MSSQL (s'il fonctionne en tant que SA), **voler** le **hash** NetNTLM ou même effectuer une **attaque** de **relais**.\
De plus, si une instance MSSQL est de confiance (lien de base de données) par une autre instance MSSQL. Si l'utilisateur a des privilèges sur la base de données de confiance, il pourra **utiliser la relation de confiance pour exécuter des requêtes également sur l'autre instance**. Ces relations de confiance peuvent être enchaînées et à un moment donné, l'utilisateur pourrait être en mesure de trouver une base de données mal configurée où il peut exécuter des commandes.\
**Les liens entre les bases de données fonctionnent même à travers les relations de confiance de forêt.**

{% content-ref url="abusing-ad-mssql.md" %}
[abusing-ad-mssql.md](abusing-ad-mssql.md)
{% endcontent-ref %}

### Délégation non contrainte

Si vous trouvez un objet Ordinateur avec l'attribut [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) et que vous avez des privilèges de domaine sur l'ordinateur, vous serez en mesure de dumper les TGT depuis la mémoire de chaque utilisateur qui se connecte à l'ordinateur.\
Donc, si un **Administrateur de domaine se connecte à l'ordinateur**, vous pourrez dumper son TGT et vous l'impliquer en utilisant [Pass the Ticket](pass-the-ticket.md).\
Grâce à la délégation contrainte, vous pourriez même **compromettre automatiquement un serveur d'impression** (espérons que ce sera un DC).

{% content-ref url="unconstrained-delegation.md" %}
[unconstrained-delegation.md](unconstrained-delegation.md)
{% endcontent-ref %}

### Délégation contrainte

Si un utilisateur ou un ordinateur est autorisé à "Délégation contrainte", il pourra **impliquer n'importe quel utilisateur pour accéder à certains services sur un ordinateur**.\
Ensuite, si vous **compromettez le hash** de cet utilisateur/ordinateur, vous pourrez **impliquer n'importe quel utilisateur** (même des administrateurs de domaine) pour accéder à certains services.

{% content-ref url="constrained-delegation.md" %}
[constrained-delegation.md](constrained-delegation.md)
{% endcontent-ref %}

### Délégation contrainte basée sur les ressources

Avoir le privilège **ÉCRIRE** sur un objet Active Directory d'un ordinateur distant permet d'obtenir une exécution de code avec des **privilèges élevés** :

{% content-ref url="resource-based-constrained-delegation.md" %}
[resource-based-constrained-delegation.md](resource-based-constrained-delegation.md)
{% endcontent-ref %}

### Abus des ACLs

L'utilisateur compromis pourrait avoir des **privilèges intéressants sur certains objets de domaine** qui pourraient vous permettre de **déplacer** latéralement/**escalader** des privilèges.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Abus du service Spooler d'impression

Découvrir un **service Spool** à l'écoute dans le domaine peut être **abusé** pour **acquérir de nouveaux identifiants** et **escalader des privilèges**.

{% content-ref url="printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](printers-spooler-service-abuse.md)
{% endcontent-ref %}

### Abus des sessions tierces

Si **d'autres utilisateurs** **accèdent** à la machine **compromise**, il est possible de **rassembler des identifiants depuis la mémoire** et même **d'injecter des balises dans leurs processus** pour les impliquer.\
En général, les utilisateurs accéderont au système via RDP, donc voici comment effectuer quelques attaques sur les sessions RDP tierces :

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### LAPS

**LAPS** fournit un système pour gérer le **mot de passe Administrateur local** sur les ordinateurs joints au domaine, garantissant qu'il est **aléatoire**, unique et fréquemment **changé**. Ces mots de passe sont stockés dans Active Directory et l'accès est contrôlé par des ACLs uniquement pour les utilisateurs autorisés. Avec des permissions suffisantes pour accéder à ces mots de passe, le pivotement vers d'autres ordinateurs devient possible.

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

### Vol de certificats

**Rassembler des certificats** depuis la machine compromise pourrait être un moyen d'escalader des privilèges à l'intérieur de l'environnement :

{% content-ref url="ad-certificates/certificate-theft.md" %}
[certificate-theft.md](ad-certificates/certificate-theft.md)
{% endcontent-ref %}

### Abus des modèles de certificats

Si des **modèles vulnérables** sont configurés, il est possible de les abuser pour escalader des privilèges :

{% content-ref url="ad-certificates/domain-escalation.md" %}
[domain-escalation.md](ad-certificates/domain-escalation.md)
{% endcontent-ref %}

## Post-exploitation avec un compte à privilèges élevés

### Dumping des identifiants de domaine

Une fois que vous obtenez des privilèges **Administrateur de domaine** ou même mieux **Administrateur d'entreprise**, vous pouvez **dumper** la **base de données de domaine** : _ntds.dit_.

[**Plus d'informations sur l'attaque DCSync peuvent être trouvées ici**](dcsync.md).

[**Plus d'informations sur la façon de voler le NTDS.dit peuvent être trouvées ici**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

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

L'**attaque Silver Ticket** crée un **ticket de service de ticket de concession (TGS)** légitime pour un service spécifique en utilisant le **hash NTLM** (par exemple, le **hash du compte PC**). Cette méthode est utilisée pour **accéder aux privilèges de service**.

{% content-ref url="silver-ticket.md" %}
[silver-ticket.md](silver-ticket.md)
{% endcontent-ref %}

### Golden Ticket

Une **attaque Golden Ticket** implique qu'un attaquant accède au **hash NTLM du compte krbtgt** dans un environnement Active Directory (AD). Ce compte est spécial car il est utilisé pour signer tous les **Tickets de concession de ticket (TGT)**, qui sont essentiels pour s'authentifier au sein du réseau AD.

Une fois que l'attaquant obtient ce hash, il peut créer des **TGT** pour n'importe quel compte de son choix (attaque Silver Ticket).

{% content-ref url="golden-ticket.md" %}
[golden-ticket.md](golden-ticket.md)
{% endcontent-ref %}

### Diamond Ticket

Ce sont comme des tickets dorés forgés d'une manière qui **contourne les mécanismes de détection des tickets dorés courants.**

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### **Persistance de compte par certificats**

**Avoir des certificats d'un compte ou être capable de les demander** est un très bon moyen de pouvoir persister dans le compte des utilisateurs (même s'il change le mot de passe) :

{% content-ref url="ad-certificates/account-persistence.md" %}
[account-persistence.md](ad-certificates/account-persistence.md)
{% endcontent-ref %}

### **Persistance de domaine par certificats**

**Utiliser des certificats est également possible pour persister avec des privilèges élevés à l'intérieur du domaine :**

{% content-ref url="ad-certificates/domain-persistence.md" %}
[domain-persistence.md](ad-certificates/domain-persistence.md)
{% endcontent-ref %}

### Groupe AdminSDHolder

L'objet **AdminSDHolder** dans Active Directory assure la sécurité des **groupes privilégiés** (comme les Administrateurs de domaine et les Administrateurs d'entreprise) en appliquant une **liste de contrôle d'accès (ACL)** standard à travers ces groupes pour prévenir les modifications non autorisées. Cependant, cette fonctionnalité peut être exploitée ; si un attaquant modifie l'ACL de l'AdminSDHolder pour donner un accès complet à un utilisateur ordinaire, cet utilisateur obtient un contrôle étendu sur tous les groupes privilégiés. Cette mesure de sécurité, censée protéger, peut donc se retourner contre elle, permettant un accès non justifié à moins d'être étroitement surveillée.

[**Plus d'informations sur le groupe AdminDSHolder ici.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### Identifiants DSRM

À l'intérieur de chaque **Contrôleur de domaine (DC)**, un compte **administrateur local** existe. En obtenant des droits d'administrateur sur une telle machine, le hash de l'administrateur local peut être extrait en utilisant **mimikatz**. Par la suite, une modification du registre est nécessaire pour **activer l'utilisation de ce mot de passe**, permettant l'accès à distance au compte Administrateur local.

{% content-ref url="dsrm-credentials.md" %}
[dsrm-credentials.md](dsrm-credentials.md)
{% endcontent-ref %}

### Persistance des ACL

Vous pourriez **donner** des **permissions spéciales** à un **utilisateur** sur certains objets de domaine spécifiques qui permettront à l'utilisateur **d'escalader des privilèges à l'avenir**.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Descripteurs de sécurité

Les **descripteurs de sécurité** sont utilisés pour **stocker** les **permissions** qu'un **objet** a **sur** un **objet**. Si vous pouvez juste **faire** un **petit changement** dans le **descripteur de sécurité** d'un objet, vous pouvez obtenir des privilèges très intéressants sur cet objet sans avoir besoin d'être membre d'un groupe privilégié.

{% content-ref url="security-descriptors.md" %}
[security-descriptors.md](security-descriptors.md)
{% endcontent-ref %}

### Clé Skeleton

Modifier **LSASS** en mémoire pour établir un **mot de passe universel**, accordant l'accès à tous les comptes de domaine.

{% content-ref url="skeleton-key.md" %}
[skeleton-key.md](skeleton-key.md)
{% endcontent-ref %}

### SSP personnalisé

[Apprenez ce qu'est un SSP (Security Support Provider) ici.](../authentication-credentials-uac-and-efs/#security-support-provider-interface-sspi)\
Vous pouvez créer votre **propre SSP** pour **capturer** en **texte clair** les **identifiants** utilisés pour accéder à la machine.\\

{% content-ref url="custom-ssp.md" %}
[custom-ssp.md](custom-ssp.md)
{% endcontent-ref %}

### DCShadow

Il enregistre un **nouveau Contrôleur de domaine** dans l'AD et l'utilise pour **pousser des attributs** (SIDHistory, SPNs...) sur des objets spécifiés **sans** laisser de **logs** concernant les **modifications**. Vous **avez besoin de privilèges DA** et d'être à l'intérieur du **domaine racine**.\
Notez que si vous utilisez de mauvaises données, des logs assez laids apparaîtront.

{% content-ref url="dcshadow.md" %}
[dcshadow.md](dcshadow.md)
{% endcontent-ref %}

### Persistance LAPS

Auparavant, nous avons discuté de la façon d'escalader des privilèges si vous avez **suffisamment de permissions pour lire les mots de passe LAPS**. Cependant, ces mots de passe peuvent également être utilisés pour **maintenir la persistance**.\
Vérifiez :

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

## Escalade de privilèges de forêt - Confiances de domaine

Microsoft considère la **forêt** comme la frontière de sécurité. Cela implique que **compromettre un seul domaine pourrait potentiellement conduire à la compromission de l'ensemble de la forêt**.

### Informations de base

Une [**confiance de domaine**](http://technet.microsoft.com/en-us/library/cc759554\(v=ws.10\).aspx) est un mécanisme de sécurité qui permet à un utilisateur d'un **domaine** d'accéder à des ressources dans un autre **domaine**. Cela crée essentiellement un lien entre les systèmes d'authentification des deux domaines, permettant aux vérifications d'authentification de circuler sans heurts. Lorsque les domaines établissent une confiance, ils échangent et conservent des **clés** spécifiques au sein de leurs **Contrôleurs de domaine (DC)**, qui sont cruciales pour l'intégrité de la confiance.

Dans un scénario typique, si un utilisateur souhaite accéder à un service dans un **domaine de confiance**, il doit d'abord demander un ticket spécial connu sous le nom de **TGT inter-realm** à partir du DC de son propre domaine. Ce TGT est crypté avec une **clé** partagée que les deux domaines ont convenue. L'utilisateur présente ensuite ce TGT au **DC du domaine de confiance** pour obtenir un ticket de service (**TGS**). Après validation réussie du TGT inter-realm par le DC du domaine de confiance, il émet un TGS, accordant à l'utilisateur l'accès au service.

**Étapes** :

1. Un **ordinateur client** dans le **Domaine 1** commence le processus en utilisant son **hash NTLM** pour demander un **Ticket Granting Ticket (TGT)** à son **Contrôleur de domaine (DC1)**.
2. DC1 émet un nouveau TGT si le client est authentifié avec succès.
3. Le client demande ensuite un **TGT inter-realm** à DC1, qui est nécessaire pour accéder aux ressources dans le **Domaine 2**.
4. Le TGT inter-realm est crypté avec une **clé de confiance** partagée entre DC1 et DC2 dans le cadre de la confiance de domaine bidirectionnelle.
5. Le client prend le TGT inter-realm au **Contrôleur de domaine du Domaine 2 (DC2)**.
6. DC2 vérifie le TGT inter-realm en utilisant sa clé de confiance partagée et, si valide, émet un **Ticket Granting Service (TGS)** pour le serveur dans le Domaine 2 auquel le client souhaite accéder.
7. Enfin, le client présente ce TGS au serveur, qui est crypté avec le hash du compte du serveur, pour obtenir l'accès au service dans le Domaine 2.

### Différentes confiances

Il est important de noter qu'une **confiance peut être unidirectionnelle ou bidirectionnelle**. Dans les options bidirectionnelles, les deux domaines se feront confiance mutuellement, mais dans la relation de confiance **unidirectionnelle**, l'un des domaines sera le **domaine de confiance** et l'autre le **domaine de confiance**. Dans ce dernier cas, **vous ne pourrez accéder qu'aux ressources à l'intérieur du domaine de confiance depuis le domaine de confiance**.

Si le Domaine A fait confiance au Domaine B, A est le domaine de confiance et B est le domaine de confiance. De plus, dans le **Domaine A**, cela serait une **confiance sortante** ; et dans le **Domaine B**, cela serait une **confiance entrante**.

**Différentes relations de confiance**

* **Confiances Parent-Enfant** : C'est une configuration courante au sein de la même forêt, où un domaine enfant a automatiquement une confiance transitive bidirectionnelle avec son domaine parent. Essentiellement, cela signifie que les demandes d'authentification peuvent circuler sans heurts entre le parent et l'enfant.
* **Confiances de liaison croisée** : Appelées "confiances de raccourci", celles-ci sont établies entre des domaines enfants pour accélérer les processus de référence. Dans des forêts complexes, les références d'authentification doivent généralement voyager jusqu'à la racine de la forêt, puis descendre vers le domaine cible. En créant des liaisons croisées, le voyage est raccourci, ce qui est particulièrement bénéfique dans des environnements géographiquement dispersés.
* **Confiances externes** : Celles-ci sont mises en place entre différents domaines non liés et sont non transitives par nature. Selon [la documentation de Microsoft](https://technet.microsoft.com/en-us/library/cc773178\(v=ws.10\).aspx), les confiances externes sont utiles pour accéder à des ressources dans un domaine en dehors de la forêt actuelle qui n'est pas connecté par une confiance de forêt. La sécurité est renforcée grâce au filtrage SID avec des confiances externes.
* **Confiances de racine d'arbre** : Ces confiances sont automatiquement établies entre le domaine racine de la forêt et une nouvelle racine d'arbre ajoutée. Bien qu'elles ne soient pas couramment rencontrées, les confiances de racine d'arbre sont importantes pour ajouter de nouveaux arbres de domaine à une forêt, leur permettant de maintenir un nom de domaine unique et garantissant une transitivité bidirectionnelle. Plus d'informations peuvent être trouvées dans [le guide de Microsoft](https://technet.microsoft.com/en-us/library/cc773178\(v=ws.10\).aspx).
* **Confiances de forêt** : Ce type de confiance est une confiance bidirectionnelle transitive entre deux domaines racines de forêt, appliquant également un filtrage SID pour renforcer les mesures de sécurité.
* **Confiances MIT** : Ces confiances sont établies avec des domaines Kerberos conformes à [RFC4120](https://tools.ietf.org/html/rfc4120) non Windows. Les confiances MIT sont un peu plus spécialisées et s'adressent aux environnements nécessitant une intégration avec des systèmes basés sur Kerberos en dehors de l'écosystème Windows.

#### Autres différences dans les **relations de confiance**

* Une relation de confiance peut également être **transitive** (A fait confiance à B, B fait confiance à C, alors A fait confiance à C) ou **non transitive**.
* Une relation de confiance peut être configurée comme une **confiance bidirectionnelle** (les deux se font confiance) ou comme une **confiance unidirectionnelle** (seulement l'un d'eux fait confiance à l'autre).

### Chemin d'attaque

1. **Énumérer** les relations de confiance
2. Vérifiez si un **principal de sécurité** (utilisateur/groupe/ordinateur) a **accès** aux ressources de l'**autre domaine**, peut-être par des entrées ACE ou en étant dans des groupes de l'autre domaine. Recherchez des **relations à travers les domaines** (la confiance a probablement été créée pour cela).
1. Kerberoast dans ce cas pourrait être une autre option.
3. **Compromettre** les **comptes** qui peuvent **pivoter** à travers les domaines.

Les attaquants pourraient accéder aux ressources dans un autre domaine par trois mécanismes principaux :

* **Membre de groupe local** : Les principaux pourraient être ajoutés à des groupes locaux sur des machines, comme le groupe "Administrateurs" sur un serveur, leur accordant un contrôle significatif sur cette machine.
* **Membre de groupe de domaine étranger** : Les principaux peuvent également être membres de groupes au sein du domaine étranger. Cependant, l'efficacité de cette méthode dépend de la nature de la confiance et de la portée du groupe.
* **Listes de contrôle d'accès (ACLs)** : Les principaux pourraient être spécifiés dans une **ACL**, en particulier en tant qu'entités dans des **ACE** au sein d'un **DACL**, leur fournissant un accès à des ressources spécifiques. Pour ceux qui souhaitent approfondir les mécanismes des ACL, DACL et ACE, le document intitulé "[An ACE Up The Sleeve](https://specterops.io/assets/resources/an\_ace\_up\_the\_sleeve.pdf)" est une ressource inestimable.

### Escalade de privilèges de forêt de l'enfant au parent
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
{% endhint %}

#### Injection de SID-History

Escaladez en tant qu'administrateur d'entreprise vers le domaine enfant/parent en abusant de la confiance avec l'injection de SID-History :

{% content-ref url="sid-history-injection.md" %}
[sid-history-injection.md](sid-history-injection.md)
{% endcontent-ref %}

#### Exploiter la Configuration NC écrivable

Comprendre comment la Configuration Naming Context (NC) peut être exploitée est crucial. La Configuration NC sert de référentiel central pour les données de configuration dans les environnements Active Directory (AD). Ces données sont répliquées à chaque contrôleur de domaine (DC) au sein de la forêt, les DC écrits maintenant une copie écrivable de la Configuration NC. Pour exploiter cela, il faut avoir **des privilèges SYSTEM sur un DC**, de préférence un DC enfant.

**Lier GPO au site DC racine**

Le conteneur Sites de la Configuration NC inclut des informations sur tous les sites des ordinateurs joints au domaine au sein de la forêt AD. En opérant avec des privilèges SYSTEM sur n'importe quel DC, les attaquants peuvent lier des GPO aux sites DC racine. Cette action compromet potentiellement le domaine racine en manipulant les politiques appliquées à ces sites.

Pour des informations approfondies, on peut explorer des recherches sur [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromettre n'importe quel gMSA dans la forêt**

Un vecteur d'attaque consiste à cibler des gMSA privilégiés au sein du domaine. La clé racine KDS, essentielle pour calculer les mots de passe des gMSA, est stockée dans la Configuration NC. Avec des privilèges SYSTEM sur n'importe quel DC, il est possible d'accéder à la clé racine KDS et de calculer les mots de passe pour n'importe quel gMSA à travers la forêt.

Une analyse détaillée peut être trouvée dans la discussion sur [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Attaque de changement de schéma**

Cette méthode nécessite de la patience, en attendant la création de nouveaux objets AD privilégiés. Avec des privilèges SYSTEM, un attaquant peut modifier le schéma AD pour accorder à n'importe quel utilisateur un contrôle total sur toutes les classes. Cela pourrait conduire à un accès non autorisé et à un contrôle sur les objets AD nouvellement créés.

Des lectures supplémentaires sont disponibles sur [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**De DA à EA avec ADCS ESC5**

La vulnérabilité ADCS ESC5 cible le contrôle des objets d'infrastructure à clé publique (PKI) pour créer un modèle de certificat qui permet l'authentification en tant que n'importe quel utilisateur au sein de la forêt. Comme les objets PKI résident dans la Configuration NC, compromettre un DC enfant écrivable permet l'exécution d'attaques ESC5.

Plus de détails à ce sujet peuvent être lus dans [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). Dans les scénarios sans ADCS, l'attaquant a la capacité de mettre en place les composants nécessaires, comme discuté dans [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
Dans ce scénario, **votre domaine est de confiance** par un domaine externe vous donnant **des permissions indéterminées** sur celui-ci. Vous devrez trouver **quels principaux de votre domaine ont quel accès sur le domaine externe** et ensuite essayer de l'exploiter :

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
Dans ce scénario, **votre domaine** **fait confiance** à certains **privilèges** d'un principal d'un **domaine différent**.

Cependant, lorsqu'un **domaine est approuvé** par le domaine de confiance, le domaine approuvé **crée un utilisateur** avec un **nom prévisible** qui utilise comme **mot de passe le mot de passe approuvé**. Ce qui signifie qu'il est possible d'**accéder à un utilisateur du domaine de confiance pour entrer dans le domaine approuvé** afin de l'énumérer et d'essayer d'escalader plus de privilèges :

{% content-ref url="external-forest-domain-one-way-outbound.md" %}
[external-forest-domain-one-way-outbound.md](external-forest-domain-one-way-outbound.md)
{% endcontent-ref %}

Une autre façon de compromettre le domaine approuvé est de trouver un [**lien SQL approuvé**](abusing-ad-mssql.md#mssql-trusted-links) créé dans la **direction opposée** de la confiance de domaine (ce qui n'est pas très courant).

Une autre façon de compromettre le domaine approuvé est d'attendre sur une machine où un **utilisateur du domaine approuvé peut accéder** pour se connecter via **RDP**. Ensuite, l'attaquant pourrait injecter du code dans le processus de session RDP et **accéder au domaine d'origine de la victime** à partir de là.\
De plus, si la **victime a monté son disque dur**, à partir du processus de **session RDP**, l'attaquant pourrait stocker des **backdoors** dans le **dossier de démarrage du disque dur**. Cette technique s'appelle **RDPInception.**

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### Atténuation de l'abus de confiance de domaine

### **Filtrage SID :**

* Le risque d'attaques exploitant l'attribut d'historique SID à travers les trusts de forêt est atténué par le filtrage SID, qui est activé par défaut sur tous les trusts inter-forêts. Cela repose sur l'hypothèse que les trusts intra-forêts sont sécurisés, considérant la forêt, plutôt que le domaine, comme la frontière de sécurité selon la position de Microsoft.
* Cependant, il y a un inconvénient : le filtrage SID peut perturber les applications et l'accès des utilisateurs, ce qui conduit à sa désactivation occasionnelle.

### **Authentification Sélective :**

* Pour les trusts inter-forêts, l'utilisation de l'authentification sélective garantit que les utilisateurs des deux forêts ne sont pas automatiquement authentifiés. Au lieu de cela, des autorisations explicites sont requises pour que les utilisateurs accèdent aux domaines et serveurs au sein du domaine ou de la forêt de confiance.
* Il est important de noter que ces mesures ne protègent pas contre l'exploitation du Contexte de Nommage de Configuration (NC) modifiable ou les attaques sur le compte de confiance.

[**Plus d'informations sur les trusts de domaine dans ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD

{% embed url="https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-lateral-movements/azure-ad-connect-hybrid-identity" %}

## Quelques Défenses Générales

[**En savoir plus sur la protection des identifiants ici.**](../stealing-credentials/credentials-protections.md)\\

### **Mesures Défensives pour la Protection des Identifiants**

* **Restrictions pour les Administrateurs de Domaine** : Il est recommandé que les Administrateurs de Domaine ne soient autorisés à se connecter qu'aux Contrôleurs de Domaine, évitant leur utilisation sur d'autres hôtes.
* **Privilèges des Comptes de Service** : Les services ne doivent pas être exécutés avec des privilèges d'Administrateur de Domaine (AD) pour maintenir la sécurité.
* **Limitation Temporelle des Privilèges** : Pour les tâches nécessitant des privilèges d'AD, leur durée doit être limitée. Cela peut être réalisé par : `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Mise en Œuvre de Techniques de Tromperie**

* La mise en œuvre de la tromperie implique de poser des pièges, comme des utilisateurs ou des ordinateurs leurres, avec des caractéristiques telles que des mots de passe qui n'expirent pas ou sont marqués comme Approuvés pour Délégation. Une approche détaillée inclut la création d'utilisateurs avec des droits spécifiques ou leur ajout à des groupes à privilèges élevés.
* Un exemple pratique implique l'utilisation d'outils comme : `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
* Plus d'informations sur le déploiement de techniques de tromperie peuvent être trouvées sur [Deploy-Deception sur GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identification de la Tromperie**

* **Pour les Objets Utilisateurs** : Les indicateurs suspects incluent un ObjectSID atypique, des connexions peu fréquentes, des dates de création et un faible nombre de mauvais mots de passe.
* **Indicateurs Généraux** : Comparer les attributs des objets leurres potentiels avec ceux des objets authentiques peut révéler des incohérences. Des outils comme [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) peuvent aider à identifier de telles tromperies.

### **Contournement des Systèmes de Détection**

* **Contournement de la Détection Microsoft ATA** :
* **Énumération des Utilisateurs** : Éviter l'énumération de session sur les Contrôleurs de Domaine pour prévenir la détection par ATA.
* **Impersonation de Ticket** : Utiliser des clés **aes** pour la création de tickets aide à éviter la détection en ne rétrogradant pas à NTLM.
* **Attaques DCSync** : Il est conseillé d'exécuter à partir d'un non-Contrôleur de Domaine pour éviter la détection par ATA, car l'exécution directe à partir d'un Contrôleur de Domaine déclenchera des alertes.

## Références

* [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
* [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{% hint style="success" %}
Apprenez et pratiquez le Hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le Hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
{% endhint %}
