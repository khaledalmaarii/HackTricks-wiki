# BloodHound et autres outils d'énumération AD

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) est issu de la suite Sysinternal :

> Un visualiseur et éditeur avancé d'Active Directory (AD). Vous pouvez utiliser AD Explorer pour naviguer facilement dans une base de données AD, définir des emplacements favoris, afficher les propriétés et les attributs d'un objet sans ouvrir de boîtes de dialogue, modifier les autorisations, afficher le schéma d'un objet et exécuter des recherches sophistiquées que vous pouvez enregistrer et réexécuter.

### Instantanés

AD Explorer peut créer des instantanés d'un AD afin que vous puissiez le vérifier hors ligne.\
Il peut être utilisé pour découvrir des vulnérabilités hors ligne ou pour comparer différents états de la base de données AD dans le temps.

Vous aurez besoin du nom d'utilisateur, du mot de passe et de la direction pour vous connecter (tout utilisateur AD est requis).

Pour prendre un instantané d'AD, allez dans `Fichier` --> `Créer un instantané` et entrez un nom pour l'instantané.

## ADRecon

****[**ADRecon**](https://github.com/adrecon/ADRecon) est un outil qui extrait et combine divers artefacts d'un environnement AD. Les informations peuvent être présentées dans un **rapport Microsoft Excel formaté spécialement** qui comprend des vues récapitulatives avec des métriques pour faciliter l'analyse et fournir une image holistique de l'état actuel de l'environnement AD cible.
```bash
# Run it
.\ADRecon.ps1
```
## BloodHound

> BloodHound est une application web Javascript à page unique, construite sur [Linkurious](http://linkurio.us), compilée avec [Electron](http://electron.atom.io), avec une base de données [Neo4j](https://neo4j.com) alimentée par un ingéreur PowerShell.
>
> BloodHound utilise la théorie des graphes pour révéler les relations cachées et souvent non intentionnelles au sein d'un environnement Active Directory. Les attaquants peuvent utiliser BloodHound pour identifier facilement des chemins d'attaque très complexes qui seraient autrement impossibles à identifier rapidement. Les défenseurs peuvent utiliser BloodHound pour identifier et éliminer ces mêmes chemins d'attaque. Les équipes bleues et rouges peuvent utiliser BloodHound pour obtenir facilement une compréhension plus profonde des relations de privilèges dans un environnement Active Directory.
>
> BloodHound est développé par [@\_wald0](https://www.twitter.com/\_wald0), [@CptJesus](https://twitter.com/CptJesus), et [@harmj0y](https://twitter.com/harmj0y).
>
> Depuis [https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)

Ainsi, [Bloodhound](https://github.com/BloodHoundAD/BloodHound) est un outil incroyable qui peut énumérer un domaine automatiquement, enregistrer toutes les informations, trouver des chemins possibles d'escalade de privilèges et afficher toutes les informations à l'aide de graphiques.

Bloodhound est composé de 2 parties principales : les **ingesteurs** et l'**application de visualisation**.

Les **ingesteurs** sont utilisés pour **énumérer le domaine et extraire toutes les informations** dans un format que l'application de visualisation comprendra.

L'**application de visualisation utilise neo4j** pour montrer comment toutes les informations sont liées et pour montrer différentes façons d'escalader les privilèges dans le domaine.

### Installation

1. Bloodhound

Pour installer l'application de visualisation, vous devrez installer **neo4j** et l'**application Bloodhound**.\
La manière la plus simple de le faire est simplement de :
```
apt-get install bloodhound
```
Vous pouvez **télécharger la version communautaire de neo4j** à partir de [ici](https://neo4j.com/download-center/#community).

1. Ingestors

Vous pouvez télécharger les Ingestors à partir de :

* https://github.com/BloodHoundAD/SharpHound/releases
* https://github.com/BloodHoundAD/BloodHound/releases
* https://github.com/fox-it/BloodHound.py

1. Apprendre le chemin à partir du graphe

Bloodhound est livré avec diverses requêtes pour mettre en évidence les chemins de compromission sensibles. Il est possible d'ajouter des requêtes personnalisées pour améliorer la recherche et la corrélation entre les objets et plus encore !

Ce référentiel contient une belle collection de requêtes : https://github.com/CompassSecurity/BloodHoundQueries

Processus d'installation :
```
$ curl -o "~/.config/bloodhound/customqueries.json" "https://raw.githubusercontent.com/CompassSecurity/BloodHoundQueries/master/BloodHound_Custom_Queries/customqueries.json"
```
### Exécution de l'application de visualisation

Après avoir téléchargé/installé les applications requises, commençons par les démarrer.\
Tout d'abord, vous devez **démarrer la base de données neo4j**:
```bash
./bin/neo4j start
#or
service neo4j start
```
La première fois que vous démarrez cette base de données, vous devrez accéder à [http://localhost:7474/browser/](http://localhost:7474/browser/). On vous demandera des identifiants par défaut (neo4j:neo4j) et vous serez **obligé de changer le mot de passe**, donc changez-le et ne l'oubliez pas.

Maintenant, démarrez l'application **bloodhound** :
```bash
./BloodHound-linux-x64
#or
bloodhound
```
Vous serez invité à saisir les identifiants de la base de données : **neo4j:\<Votre nouveau mot de passe>**

Et Bloodhound sera prêt à ingérer des données.

![](<../../.gitbook/assets/image (171) (1).png>)

### SharpHound

Ils ont plusieurs options, mais si vous voulez exécuter SharpHound à partir d'un PC joint au domaine, en utilisant votre utilisateur actuel et extraire toutes les informations possibles, vous pouvez faire :
```
./SharpHound.exe --CollectionMethods All
Invoke-BloodHound -CollectionMethod All
```
Vous pouvez en savoir plus sur **CollectionMethod** et la session de boucle [ici](https://bloodhound.readthedocs.io/en/latest/data-collection/sharphound-all-flags.html).

Si vous souhaitez exécuter SharpHound en utilisant des identifiants différents, vous pouvez créer une session CMD netonly et exécuter SharpHound à partir de là :
```
runas /netonly /user:domain\user "powershell.exe -exec bypass"
```
[**En savoir plus sur Bloodhound sur ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux)

**Silencieux sous Windows**

### **Python bloodhound**

Si vous avez des identifiants de domaine, vous pouvez exécuter un **ingesteur python bloodhound depuis n'importe quelle plateforme** afin de ne pas dépendre de Windows.\
Téléchargez-le depuis [https://github.com/fox-it/BloodHound.py](https://github.com/fox-it/BloodHound.py) ou en faisant `pip3 install bloodhound`
```bash
bloodhound-python -u support -p '#00^BlackKnight' -ns 10.10.10.192 -d blackfield.local -c all
```
Si vous l'exécutez via proxychains, ajoutez `--dns-tcp` pour que la résolution DNS fonctionne via le proxy.
```bash
proxychains bloodhound-python -u support -p '#00^BlackKnight' -ns 10.10.10.192 -d blackfield.local -c all --dns-tcp
```
### Python SilentHound

Ce script permet de **récupérer silencieusement des informations sur un domaine Active Directory via LDAP** en analysant les utilisateurs, les administrateurs, les groupes, etc.

Consultez-le sur [**SilentHound github**](https://github.com/layer8secure/SilentHound).

### RustHound

BloodHound en Rust, [**consultez-le ici**](https://github.com/OPENCYBER-FR/RustHound).

## Group3r

[**Group3r**](https://github.com/Group3r/Group3r) **** est un outil pour trouver des **vulnérabilités** dans les **stratégies de groupe** associées à Active Directory. \
Vous devez **exécuter group3r** à partir d'un hôte à l'intérieur du domaine en utilisant **n'importe quel utilisateur de domaine**.
```bash
group3r.exe -f <filepath-name.log> 
# -s sends results to stdin
# -f send results to file
```
## PingCastle

****[**PingCastle**](https://www.pingcastle.com/documentation/) **évalue la posture de sécurité d'un environnement AD** et fournit un **rapport** agréable avec des graphiques.

Pour l'exécuter, vous pouvez exécuter le binaire `PingCastle.exe` et il démarrera une **session interactive** présentant un menu d'options. L'option par défaut à utiliser est **`healthcheck`** qui établira une **vue d'ensemble** de **domaine**, et trouvera des **mauvaises configurations** et des **vulnérabilités**.&#x20;

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
