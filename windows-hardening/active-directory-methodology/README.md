# Méthodologie Active Directory

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Aperçu de base

Active Directory permet aux administrateurs réseau de créer et de gérer des domaines, des utilisateurs et des objets au sein d'un réseau. Par exemple, un administrateur peut créer un groupe d'utilisateurs et leur donner des privilèges d'accès spécifiques à certains répertoires sur le serveur. À mesure que le réseau se développe, Active Directory fournit un moyen d'organiser un grand nombre d'utilisateurs en groupes et sous-groupes logiques, tout en fournissant un contrôle d'accès à chaque niveau.

La structure de l'Active Directory comprend trois niveaux principaux : 1) les domaines, 2) les arbres et 3) les forêts. Plusieurs objets (utilisateurs ou périphériques) qui utilisent tous la même base de données peuvent être regroupés dans un seul domaine. Plusieurs domaines peuvent être combinés en un seul groupe appelé arbre. Plusieurs arbres peuvent être regroupés en une collection appelée forêt. Chacun de ces niveaux peut se voir attribuer des droits d'accès spécifiques et des privilèges de communication.

Les principaux concepts d'un Active Directory :

1. **Répertoire** - Contient toutes les informations sur les objets de l'Active Directory
2. **Objet** - Un objet fait référence à presque tout ce qui se trouve dans le répertoire (un utilisateur, un groupe, un dossier partagé...)
3. **Domaine** - Les objets du répertoire sont contenus dans le domaine. À l'intérieur d'une "forêt", plus d'un domaine peut exister et chacun d'eux aura sa propre collection d'objets.
4. **Arbre** - Groupe de domaines avec la même racine. Exemple : _dom.local, email.dom.local, www.dom.local_
5. **Forêt** - La forêt est le niveau le plus élevé de la hiérarchie de l'organisation et est composée d'un groupe d'arbres. Les arbres sont reliés par des relations de confiance.

Active Directory fournit plusieurs services différents, qui relèvent de l'ensemble de services de domaine Active Directory, ou AD DS. Ces services comprennent :

1. **Services de domaine** - stocke des données centralisées et gère la communication entre les utilisateurs et les domaines ; comprend l'authentification de connexion et la fonctionnalité de recherche
2. **Services de certificats** - crée, distribue et gère des certificats sécurisés
3. **Services de répertoire léger** - prend en charge les applications activées par annuaire en utilisant le protocole ouvert (LDAP)
4. **Services de fédération de répertoires** - fournit une authentification unique (SSO) pour authentifier un utilisateur dans plusieurs applications Web au cours d'une seule session
5. **Gestion des droits** - protège les informations protégées par le droit d'auteur en empêchant une utilisation et une distribution non autorisées de contenu numérique
6. **Service DNS** - Utilisé pour résoudre les noms de domaine.

AD DS est inclus avec Windows Server (y compris Windows Server 10) et est conçu pour gérer les systèmes clients. Bien que les systèmes exécutant la version régulière de Windows n'aient pas les fonctionnalités administratives d'AD DS, ils prennent en charge Active Directory. Cela signifie que tout ordinateur Windows peut se connecter à un groupe de travail Windows, à condition que l'utilisateur dispose des informations d'identification de connexion correctes.\
**De :** [**https://techterms.com/definition/active\_directory**](https://techterms.com/definition/active\_directory)

### **Authentification Kerberos**

Pour apprendre à **attaquer un AD**, vous devez **comprendre** très bien le **processus d'authentification Kerberos**.\
[Lisez cette page si vous ne savez toujours pas comment cela fonctionne.](kerberos-authentication.md)

## Feuille de triche

Vous pouvez aller sur [https://wadcoms.github.io/](https://wadcoms.github.io) pour avoir une vue rapide des commandes que vous pouvez exécuter pour énumérer/exploiter un AD.

## Reconnaissance Active Directory (Pas de credentials/sessions)

Si vous avez simplement accès à un environnement AD mais que vous n'avez pas de credentials/sessions, vous pouvez :

* **Pentester le réseau :**
  * Analysez le réseau, trouvez les machines et les ports ouverts et essayez d'**exploiter les vulnérabilités** ou d'**extraire des informations d'identification** à partir d'elles (par exemple, [les imprimantes pourraient être des cibles très intéressantes](ad-information-in-printers.md)).
  * L'énumération DNS peut donner des informations sur les serveurs clés du domaine tels que le web, les imprimantes, les partages, le VPN, les médias, etc.
    * `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/D
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
```
* **Serveur OWA (Outlook Web Access)**

Si vous trouvez l'un de ces serveurs sur le réseau, vous pouvez également effectuer une **énumération des utilisateurs** contre celui-ci. Par exemple, vous pourriez utiliser l'outil [**MailSniper**](https://github.com/dafthack/MailSniper):
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
Vous pouvez trouver des listes de noms d'utilisateurs dans [**ce dépôt Github**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) et dans celui-ci ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).

Cependant, vous devriez avoir le **nom des personnes travaillant dans l'entreprise** à partir de l'étape de reconnaissance que vous auriez dû effectuer avant cela. Avec le nom et le prénom, vous pouvez utiliser le script [**namemash.py**](https://gist.github.com/superkojiman/11076951) pour générer des noms d'utilisateurs potentiellement valides.
{% endhint %}

### Connaître un ou plusieurs noms d'utilisateurs

Ok, donc vous savez que vous avez déjà un nom d'utilisateur valide mais pas de mot de passe... Alors essayez :

* [**ASREPRoast**](asreproast.md) : Si un utilisateur **n'a pas** l'attribut _DONT\_REQ\_PREAUTH_, vous pouvez **demander un message AS\_REP** pour cet utilisateur qui contiendra des données chiffrées par une dérivation du mot de passe de l'utilisateur.
* [**Password Spraying**](password-spraying.md) : Essayez les mots de passe les plus **courants** avec chacun des utilisateurs découverts, peut-être qu'un utilisateur utilise un mauvais mot de passe (gardez à l'esprit la politique de mot de passe !).
  * Notez que vous pouvez également **pulvériser les serveurs OWA** pour essayer d'accéder aux serveurs de messagerie des utilisateurs.

{% content-ref url="password-spraying.md" %}
[password-spraying.md](password-spraying.md)
{% endcontent-ref %}

### Empoisonnement LLMNR/NBT-NS

Vous pourriez être en mesure d'**obtenir** certains **hashes de challenge** à craquer en **empoisonnant** certains protocoles du **réseau** :

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

### NTML Relay

Si vous avez réussi à énumérer l'annuaire actif, vous aurez **plus d'adresses e-mail et une meilleure compréhension du réseau**. Vous pourriez être en mesure de forcer des [**attaques de relais NTML**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) \*\*\*\* pour accéder à l'environnement AD.

### Vol de crédits NTLM

Si vous pouvez **accéder à d'autres PC ou partages** avec l'utilisateur **null ou guest**, vous pouvez **placer des fichiers** (comme un fichier SCF) qui, s'ils sont accédés d'une certaine manière, déclencheront une authentification NTML contre vous afin que vous puissiez **voler** le **challenge NTLM** pour le craquer :

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

## Énumération de l'Active Directory AVEC des crédits/session

Pour cette phase, vous devez avoir **compromis les crédits ou une session d'un compte de domaine valide**. Si vous avez des crédits valides ou une session en tant qu'utilisateur de domaine, **vous devez vous rappeler que les options données précédemment sont toujours des options pour compromettre d'autres utilisateurs**.

Avant de commencer l'énumération authentifiée, vous devez savoir ce qu'est le **problème de double saut Kerberos**.

{% content-ref url="kerberos-double-hop-problem.md" %}
[kerberos-double-hop-problem.md](kerberos-double-hop-problem.md)
{% endcontent-ref %}

### Énumération

Avoir compromis un compte est une **grande étape pour commencer à compromettre l'ensemble du domaine**, car vous allez être en mesure de commencer l'**énumération de l'Active Directory** :

En ce qui concerne [**ASREPRoast**](asreproast.md), vous pouvez maintenant trouver tous les utilisateurs vulnérables possibles, et en ce qui concerne [**Password Spraying**](password-spraying.md), vous pouvez obtenir une **liste de tous les noms d'utilisateurs** et essayer le mot de passe du compte compromis, les mots de passe vides et les nouveaux mots de passe prometteurs.

* Vous pouvez utiliser le [**CMD pour effectuer une reconnaissance de base**](../basic-cmd-for-pentesters.md#domain-info)
* Vous pouvez également utiliser [**powershell pour la reconnaissance**](../basic-powershell-for-pentesters/) qui sera plus furtif
* Vous pouvez également [**utiliser powerview**](../basic-powershell-for-pentesters/powerview.md) pour extraire des informations plus détaillées
* Un autre outil incroyable pour la reconnaissance dans un annuaire actif est [**BloodHound**](bloodhound.md). Il n'est **pas très furtif** (selon les méthodes de collecte que vous utilisez), mais **si cela ne vous dérange pas**, vous devriez absolument l'essayer. Trouvez où les utilisateurs peuvent se connecter en RDP, trouvez le chemin vers d'autres groupes, etc.
  * **D'autres outils d'énumération AD automatisés sont :** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
* \*\*\*\*[**Enregistrements DNS de l'AD**](ad-dns-records.md) \*\*\*\* car ils peuvent contenir des informations intéressantes.
* Un **outil avec GUI** que vous pouvez utiliser pour énumérer l'annuaire est **AdExplorer.exe** de la suite **SysInternal**.
* Vous pouvez également rechercher dans la base de données LDAP avec **ldapsearch** pour rechercher des informations d'identification dans les champs _userPassword_ & _unixUserPassword_, ou même pour _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) pour d'autres méthodes.
* Si vous utilisez **Linux**, vous pouvez également énumérer le domaine en utilisant [**pywerview**](https://github.com/the-useless-one/pywerview).
* Vous pouvez également essayer des outils automatisés tels que :
  * [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  * [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
*   **Extraction de tous les utilisateurs du domaine**

    Il est très facile d'obtenir tous les noms d'utilisateur du domaine à partir de Windows (`net user /domain`, `Get-DomainUser` ou `wmic useraccount get name,sid`). Sous Linux, vous pouvez utiliser : `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ou `enum4linux -a -u "user" -p "password" <DC IP>`

> Même si cette section d'énumération semble petite, c'est la partie la plus importante de toutes. Accédez aux liens (principalement celui de cmd, powershell, powerview et BloodHound), apprenez à énumérer un domaine et pratiquez jusqu'à ce que vous vous sentiez à l'aise. Pendant une évaluation, ce sera le moment clé pour trouver votre chemin vers DA ou pour décider que rien ne peut être fait.

### Kerberoast

L'objectif de Kerberoasting est de récolter des **tickets TGS pour les services qui s'exécutent au nom des comptes d'utilisateurs de domaine**. Une
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTML Relay

Si vous avez réussi à énumérer l'Active Directory, vous aurez **plus d'e-mails et une meilleure compréhension du réseau**. Vous pourriez être en mesure de forcer des [**attaques de relais NTML**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### **Recherche de crédits dans les partages d'ordinateurs**

Maintenant que vous avez des informations d'identification de base, vous devriez vérifier si vous pouvez **trouver** des **fichiers intéressants partagés dans l'AD**. Vous pourriez le faire manuellement, mais c'est une tâche très ennuyeuse et répétitive (surtout si vous trouvez des centaines de documents que vous devez vérifier).

[**Suivez ce lien pour en savoir plus sur les outils que vous pourriez utiliser.**](../../network-services-pentesting/pentesting-smb.md#domain-shared-folders-search)

### Vol de crédits NTLM

Si vous pouvez **accéder à d'autres PC ou partages**, vous pouvez **placer des fichiers** (comme un fichier SCF) qui, s'ils sont accédés d'une manière ou d'une autre, déclencheront une **authentification NTML contre vous** afin que vous puissiez **voler** le **défi NTLM** pour le casser :

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Cette vulnérabilité permettait à n'importe quel utilisateur authentifié de **compromettre le contrôleur de domaine**.

{% content-ref url="printnightmare.md" %}
[printnightmare.md](printnightmare.md)
{% endcontent-ref %}

## Élévation de privilèges sur Active Directory AVEC des privilèges/une session privilégiée

**Pour les techniques suivantes, un utilisateur de domaine régulier ne suffit pas, vous avez besoin de certains privilèges/identifiants spéciaux pour effectuer ces attaques.**

### Extraction de hachage

Espérons que vous avez réussi à **compromettre un compte administrateur local** en utilisant [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) y compris le relais, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalade de privilèges locaux](../windows-local-privilege-escalation/).\
Ensuite, il est temps de récupérer tous les hachages en mémoire et localement.\
[**Lisez cette page sur les différentes façons d'obtenir les hachages.**](broken-reference)

### Pass the Hash

**Une fois que vous avez le hachage d'un utilisateur**, vous pouvez l'utiliser pour **l'usurper**.\
Vous devez utiliser un **outil** qui **effectuera** l'**authentification NTLM en utilisant** ce **hachage**, **ou** vous pourriez créer une nouvelle **sessionlogon** et **injecter** ce **hachage** à l'intérieur de **LSASS**, de sorte que lorsque toute **authentification NTLM est effectuée**, ce **hachage sera utilisé**. La dernière option est ce que fait mimikatz.\
[**Lisez cette page pour plus d'informations.**](../ntlm/#pass-the-hash)

### Over Pass the Hash/Pass the Key

Cette attaque vise à **utiliser le hachage NTLM de l'utilisateur pour demander des tickets Kerberos**, comme alternative au protocole Pass The Hash courant sur le protocole NTLM. Par conséquent, cela pourrait être particulièrement **utile dans les réseaux où le protocole NTLM est désactivé** et où seul **Kerberos est autorisé** en tant que protocole d'authentification.

{% content-ref url="over-pass-the-hash-pass-the-key.md" %}
[over-pass-the-hash-pass-the-key.md](over-pass-the-hash-pass-the-key.md)
{% endcontent-ref %}

### Pass the Ticket

Cette attaque est similaire à Pass the Key, mais au lieu d'utiliser des hachages pour demander un ticket, le **ticket lui-même est volé** et utilisé pour s'authentifier en tant que propriétaire.

{% content-ref url="pass-the-ticket.md" %}
[pass-the-ticket.md](pass-the-ticket.md)
{% endcontent-ref %}

### Réutilisation des identifiants

Si vous avez le **hachage** ou le **mot de passe** d'un **administrateur local**, vous devriez essayer de **vous connecter localement** à d'autres **PC** avec celui-ci.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
{% hint style="warning" %}
Notez que cela est assez **bruyant** et que **LAPS** le **mitigerait**.
{% endhint %}

### Abus MSSQL et liens de confiance

Si un utilisateur a des privilèges pour **accéder aux instances MSSQL**, il pourrait être en mesure de l'utiliser pour **exécuter des commandes** dans l'hôte MSSQL (s'il s'exécute en tant que SA), **voler** le **hash NetNTLM** ou même effectuer une **attaque de relais**.\
De plus, si une instance MSSQL est approuvée (lien de base de données) par une autre instance MSSQL. Si l'utilisateur a des privilèges sur la base de données approuvée, il pourra **utiliser la relation de confiance pour exécuter des requêtes également dans l'autre instance**. Ces relations de confiance peuvent être enchaînées et à un moment donné, l'utilisateur pourrait être en mesure de trouver une base de données mal configurée où il peut exécuter des commandes.\
**Les liens entre les bases de données fonctionnent même à travers les relations de forêt.**

{% content-ref url="abusing-ad-mssql.md" %}
[abusing-ad-mssql.md](abusing-ad-mssql.md)
{% endcontent-ref %}

### Délégation non contrainte

Si vous trouvez un objet d'ordinateur avec l'attribut [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) et que vous avez des privilèges de domaine sur l'ordinateur, vous pourrez extraire les TGT de la mémoire de chaque utilisateur qui se connecte à l'ordinateur.\
Ainsi, si un **administrateur de domaine se connecte à l'ordinateur**, vous pourrez extraire son TGT et vous faire passer pour lui en utilisant [Pass the Ticket](pass-the-ticket.md).\
Grâce à la délégation contrainte, vous pourriez même **compromettre automatiquement un serveur d'impression** (espérons que ce sera un DC).

{% content-ref url="unconstrained-delegation.md" %}
[unconstrained-delegation.md](unconstrained-delegation.md)
{% endcontent-ref %}

### Délégation contrainte

Si un utilisateur ou un ordinateur est autorisé pour la "délégation contrainte", il sera en mesure d'**usurper l'identité de n'importe quel utilisateur pour accéder à certains services sur un ordinateur**.\
Ensuite, si vous **compromettez le hash** de cet utilisateur/ordinateur, vous pourrez **usurper l'identité de n'importe quel utilisateur** (même des administrateurs de domaine) pour accéder à certains services.

{% content-ref url="constrained-delegation.md" %}
[constrained-delegation.md](constrained-delegation.md)
{% endcontent-ref %}

### Délégation contrainte basée sur les ressources

Il est possible d'obtenir une exécution de code avec des **privilèges élevés sur un ordinateur distant si vous avez le privilège WRITE** sur l'objet AD de cet ordinateur.

{% content-ref url="resource-based-constrained-delegation.md" %}
[resource-based-constrained-delegation.md](resource-based-constrained-delegation.md)
{% endcontent-ref %}

### Abus des ACL

L'utilisateur compromis pourrait avoir certains **privilèges intéressants sur certains objets de domaine** qui pourraient vous permettre de **vous déplacer** latéralement/**d'escalader** les privilèges.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Abus du service Spooler d'impression

Si vous pouvez trouver un **service Spooler d'impression en écoute** à l'intérieur du domaine, vous pourrez peut-être l'**utiliser** pour **obtenir de nouvelles informations d'identification** et **escalader les privilèges**.\
[**Plus d'informations sur la façon d'abuser des services Spooler ici.**](printers-spooler-service-abuse.md)

### Abus de sessions tierces

Si **d'autres utilisateurs accèdent** à la **machine compromise**, il est possible de **recueillir des informations d'identification à partir de la mémoire
### Différentes relations de confiance

Il est important de noter qu'une confiance peut être à sens unique ou à double sens. Dans les options à double sens, les deux domaines se feront confiance, mais dans la relation de confiance à sens unique, l'un des domaines sera le domaine de confiance et l'autre le domaine de confiance. Dans ce dernier cas, vous ne pourrez accéder qu'aux ressources à l'intérieur du domaine de confiance à partir du domaine de confiance.

Si le domaine A fait confiance au domaine B, A est le domaine de confiance et B est le domaine de confiance. De plus, dans le domaine A, il s'agirait d'une confiance sortante ; et dans le domaine B, il s'agirait d'une confiance entrante.

**Différentes relations de confiance**

* **Parent-Enfant** - faisant partie de la même forêt - un domaine enfant conserve une confiance transitive à deux sens implicite avec son parent. C'est probablement le type de confiance le plus courant que vous rencontrerez.
* **Liaison croisée** - alias une "confiance de raccourci" entre les domaines enfants pour améliorer les temps de référence. Normalement, les références dans une forêt complexe doivent filtrer jusqu'à la racine de la forêt, puis redescendre vers le domaine cible, donc pour un scénario géographiquement étalé, les liaisons croisées peuvent être utiles pour réduire les temps d'authentification.
* **Externe** - une confiance implicitement non transitive créée entre des domaines disparates. "Les confiances externes fournissent un accès aux ressources dans un domaine en dehors de la forêt qui n'est pas déjà rejoint par une confiance de forêt." Les confiances externes appliquent le filtrage SID, une protection de sécurité couverte plus tard dans ce post.
* **Racine d'arbre** - une confiance transitive implicite à deux sens entre la racine de la forêt et la nouvelle racine d'arbre que vous ajoutez. Je n'ai pas rencontré de confiance racine d'arbre trop souvent, mais d'après la documentation de Microsoft, elles sont créées lorsque vous créez une nouvelle arborescence de domaine dans une forêt. Ce sont des confiances intra-forêt, et elles préservent la transitivité à deux sens tout en permettant à l'arbre d'avoir un nom de domaine distinct (au lieu de enfant.parent.com).
* **Forêt** - une confiance transitive entre deux domaines racine de forêt. Les confiances de forêt appliquent également le filtrage SID.
* **MIT** - une confiance avec un domaine Kerberos non-Windows conforme à [RFC4120](https://tools.ietf.org/html/rfc4120). J'espère plonger plus en profondeur dans les confiances MIT à l'avenir.

#### Autres différences dans les relations de confiance

* Une relation de confiance peut également être transitive (A fait confiance à B, B fait confiance à C, alors A fait confiance à C) ou non transitive.
* Une relation de confiance peut être configurée en tant que confiance bidirectionnelle (les deux se font confiance) ou en tant que confiance unidirectionnelle (un seul d'entre eux fait confiance à l'autre).

### Chemin d'attaque

1. **Énumérez** les relations de confiance
2. Vérifiez si un **principal de sécurité** (utilisateur/groupe/ordinateur) a **accès** aux ressources de l'**autre domaine**, peut-être par des entrées ACE ou en étant dans des groupes de l'autre domaine. Recherchez des **relations entre les domaines** (la confiance a été créée pour cela probablement).
   1. Kerberoast dans ce cas pourrait être une autre option.
3. **Compromettez** les **comptes** qui peuvent **pivoter** à travers les domaines.

Il existe trois **principales** façons pour les principaux de sécurité (utilisateurs/groupes/ordinateurs) d'un domaine d'avoir accès aux ressources dans un autre domaine étranger/de confiance :

* Ils peuvent être ajoutés à des **groupes locaux** sur des machines individuelles, c'est-à-dire le groupe "Administrateurs" local sur un serveur.
* Ils peuvent être ajoutés à des **groupes dans le domaine étranger**. Il y a quelques mises en garde en fonction du type de confiance et de la portée du groupe, décrites brièvement.
* Ils peuvent être ajoutés en tant que principaux dans une **liste de contrôle d'accès**, plus intéressant pour nous en tant que principaux dans les **ACE** dans un **DACL**. Pour plus d'informations sur les ACL/DACL/ACE, consultez le document blanc "[An ACE Up The Sleeve](https://specterops.io/assets/resources/an\_ace\_up\_the\_sleeve.pdf)".
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
Vous pouvez trouver celle utilisée par le domaine actuel avec:
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

#### Exploitation de Configuration NC en écriture

Le Configuration NC est le référentiel principal pour les informations de configuration d'une forêt et est répliqué sur chaque DC de la forêt. De plus, chaque DC inscriptible (pas les DC en lecture seule) de la forêt détient une copie inscriptible de la Configuration NC. L'exploitation de cela nécessite l'exécution en tant que SYSTEM sur un DC (enfant).

Il est possible de compromettre le domaine racine de diverses manières. Exemples :

* [Lier une GPO au site du DC racine](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research)
* [Compromettre gMSA](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)
* [Attaque de schéma](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent)
* Exploiter ADCS - Créer/modifier un modèle de certificat pour permettre l'authentification en tant que n'importe quel utilisateur (par exemple, les administrateurs d'entreprise)

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
Dans ce scénario, **votre domaine est de confiance** par un domaine externe vous donnant des **permissions indéterminées** sur celui-ci. Vous devrez trouver **quels principaux de votre domaine ont quel accès sur le domaine externe** et ensuite essayer de l'exploiter :

{% content-ref url="external-forest-domain-oneway-inbound.md" %}
[external-forest-domain-oneway-inbound.md](external-forest-domain-oneway-inbound.md)
{% endcontent-ref %}

### Domaine de la forêt externe - Un sens (sortant)
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
Dans ce scénario, **votre domaine** accorde une certaine **confiance** à un principal provenant de **différents domaines**.

Cependant, lorsqu'un **domaine est approuvé** par le domaine de confiance, le domaine approuvé **crée un utilisateur** avec un **nom prévisible** qui utilise comme **mot de passe le mot de passe de confiance**. Ce qui signifie qu'il est possible d'**accéder à un utilisateur du domaine de confiance pour accéder au domaine approuvé** afin de l'énumérer et d'essayer d'escalader davantage de privilèges :

{% content-ref url="external-forest-domain-one-way-outbound.md" %}
[external-forest-domain-one-way-outbound.md](external-forest-domain-one-way-outbound.md)
{% endcontent-ref %}

Une autre façon de compromettre le domaine approuvé est de trouver un [**lien de confiance SQL**](abusing-ad-mssql.md#mssql-trusted-links) créé dans la **direction opposée** de la confiance de domaine (ce qui n'est pas très courant).

Une autre façon de compromettre le domaine approuvé est d'attendre dans une machine où un **utilisateur du domaine approuvé peut accéder** pour se connecter via **RDP**. Ensuite, l'attaquant pourrait injecter du code dans le processus de session RDP et **accéder au domaine d'origine de la victime** à partir de là.\
De plus, si la **victime a monté son disque dur**, à partir du processus de session RDP, l'attaquant pourrait stocker des **backdoors** dans le **dossier de démarrage du disque dur**. Cette technique s'appelle **RDPInception.**

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### Atténuation de l'abus de confiance de domaine

**Filtrage SID :**

* Éviter les attaques qui abusent de l'attribut d'historique SID à travers la confiance de la forêt.
* Activé par défaut sur toutes les confiances inter-forêts. Les confiances intra-forêts sont considérées comme sécurisées par défaut (MS considère que la forêt et non le domaine est une limite de sécurité).
* Cependant, étant donné que le filtrage SID a le potentiel de perturber les applications et l'accès des utilisateurs, il est souvent désactivé.
* Authentification sélective
  * Dans une confiance inter-forêt, si l'authentification sélective est configurée, les utilisateurs entre les confiances ne seront pas automatiquement authentifiés. L'accès individuel aux domaines et serveurs dans le domaine/forêt de confiance doit être donné.
* Ne prévient pas l'exploitation de la NC de configuration inscriptible et l'attaque de compte de confiance.

[**Plus d'informations sur les confiances de domaine dans ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Cloud & Cloud -> AD

{% embed url="https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-lateral-movements/azure-ad-connect-hybrid-identity" %}

## Quelques défenses générales

[**En savoir plus sur la protection des informations d'identification ici.**](../stealing-credentials/credentials-protections.md)\
**Veuillez trouver des migrations contre chaque technique dans la description de la technique.**

* Ne pas permettre aux administrateurs de domaine de se connecter sur d'autres hôtes que les contrôleurs de domaine
* Ne jamais exécuter un service avec des privilèges DA
* Si vous avez besoin de privilèges d'administrateur de domaine, limitez le temps : `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### Tromperie

* Le mot de passe n'expire pas
* Approuvé pour la délégation
* Utilisateurs avec SPN
* Mot de passe dans la description
* Utilisateurs qui sont membres de groupes à haut privilège
* Utilisateurs avec des droits ACL sur d'autres utilisateurs, groupes ou conteneurs
* Objets d'ordinateur
* ...
* [https://github.com/samratashok/Deploy-Deception](https://github.com/samratashok/Deploy-Deception)
  * `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`

## Comment identifier la tromperie

**Pour les objets utilisateur :**

* ObjectSID (différent du domaine)
* lastLogon, lastlogontimestamp
* Logoncount (un nombre très faible est suspect)
* whenCreated
* Badpwdcount (un nombre très faible est suspect)

**Général :**

* Certaines solutions remplissent toutes les attributs possibles avec des informations. Par exemple, comparez les attributs d'un objet d'ordinateur avec l'attribut d'un objet d'ordinateur 100% réel comme DC. Ou les utilisateurs contre le RID 500 (administrateur par défaut).
* Vérifiez si quelque chose est trop beau pour être vrai
* [https://github.com/JavelinNetworks/HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster)

### Contourner la détection Microsoft ATA

#### Énumération des utilisateurs

ATA ne se plaint que lorsque vous essayez d'énumérer des sessions dans le DC, donc si vous ne cherchez pas de sessions dans le DC mais dans le reste des hôtes, vous ne serez probablement pas détecté.

#### Création d'impersonnations de tickets (Over pass the hash, golden ticket...)

Créez toujours les tickets en utilisant les clés **aes** également car ce que ATA identifie comme malveillant est la dégradation en NTLM.

#### DCSync

Si vous n'exécutez pas cela à partir d'un contrôleur de domaine, ATA va vous attraper, désolé.

## Plus d'outils

* [Script Powershell pour automatiser l'audit de domaine](https://github.com/phillips321/adaudit)
* [Script Python pour énumérer Active Directory](https://github.com/ropnop/windapsearch)
* [Script Python pour énumérer Active Directory](https://github.com/CroweCybersecurity/ad-ldap-enum)

## Références

* [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs.
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
