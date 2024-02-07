# BloodHound & Autres Outils d'Énumération AD

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> - <a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou souhaitez-vous avoir accès à la **dernière version du PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord**](https://discord.gg/hRep4RUj7f) ou le **groupe Telegram**](https://t.me/peass) ou **suivez-moi** sur **Twitter** **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et au [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Explorateur AD

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) est issu de la Suite Sysinternal :

> Un visualiseur et éditeur avancé d'Active Directory (AD). Vous pouvez utiliser AD Explorer pour naviguer facilement dans une base de données AD, définir des emplacements favoris, afficher les propriétés et attributs des objets sans ouvrir de boîtes de dialogue, éditer les autorisations, afficher le schéma d'un objet et exécuter des recherches sophistiquées que vous pouvez enregistrer et réexécuter.

### Instantanés

AD Explorer peut créer des instantanés d'un AD pour que vous puissiez le vérifier hors ligne.\
Il peut être utilisé pour découvrir des vulnérabilités hors ligne, ou pour comparer différents états de la base de données AD à travers le temps.

Vous aurez besoin du nom d'utilisateur, du mot de passe et de la direction pour vous connecter (un utilisateur AD est requis).

Pour prendre un instantané de l'AD, allez dans `Fichier` --> `Créer un instantané` et saisissez un nom pour l'instantané.

## ADRecon

[**ADRecon**](https://github.com/adrecon/ADRecon) est un outil qui extrait et combine divers artefacts d'un environnement AD. Les informations peuvent être présentées dans un **rapport Microsoft Excel spécialement formaté** qui inclut des vues récapitulatives avec des métriques pour faciliter l'analyse et fournir une image holistique de l'état actuel de l'environnement AD cible.
```bash
# Run it
.\ADRecon.ps1
```
## BloodHound

> BloodHound est une application web monolithique composée d'une interface React intégrée avec [Sigma.js](https://www.sigmajs.org/) et d'une API REST basée sur [Go](https://go.dev/). Elle est déployée avec une base de données d'application [Postgresql](https://www.postgresql.org/) et une base de données graphique [Neo4j](https://neo4j.com), et est alimentée par les collecteurs de données [SharpHound](https://github.com/BloodHoundAD/SharpHound) et [AzureHound](https://github.com/BloodHoundAD/AzureHound).
>
>BloodHound utilise la théorie des graphes pour révéler les relations cachées et souvent non intentionnelles au sein d'un environnement Active Directory ou Azure. Les attaquants peuvent utiliser BloodHound pour identifier facilement des chemins d'attaque très complexes qui seraient autrement impossibles à identifier rapidement. Les défenseurs peuvent utiliser BloodHound pour identifier et éliminer ces mêmes chemins d'attaque. Les équipes bleues et rouges peuvent utiliser BloodHound pour obtenir facilement une compréhension plus approfondie des relations de privilèges dans un environnement Active Directory ou Azure.
>
>BloodHound CE est créé et maintenu par l'équipe [BloodHound Enterprise Team](https://bloodhoundenterprise.io). Le BloodHound original a été créé par [@\_wald0](https://www.twitter.com/\_wald0), [@CptJesus](https://twitter.com/CptJesus), et [@harmj0y](https://twitter.com/harmj0y).
>
>De [https://github.com/SpecterOps/BloodHound](https://github.com/SpecterOps/BloodHound)

Ainsi, [Bloodhound](https://github.com/SpecterOps/BloodHound) est un outil incroyable qui peut énumérer un domaine automatiquement, enregistrer toutes les informations, trouver des chemins potentiels d'escalade de privilèges et afficher toutes les informations à l'aide de graphiques.

Bloodhound est composé de 2 parties principales : les **ingestors** et l'**application de visualisation**.

Les **ingestors** sont utilisés pour **énumérer le domaine et extraire toutes les informations** dans un format que l'application de visualisation comprendra.

L'**application de visualisation utilise neo4j** pour montrer comment toutes les informations sont liées et pour montrer différentes façons d'escalader les privilèges dans le domaine.

### Installation
Après la création de BloodHound CE, l'ensemble du projet a été mis à jour pour faciliter son utilisation avec Docker. La manière la plus simple de commencer est d'utiliser sa configuration Docker Compose préconfigurée.

1. Installez Docker Compose. Cela devrait être inclus dans l'installation de [Docker Desktop](https://www.docker.com/products/docker-desktop/).
2. Exécutez :
```
curl -L https://ghst.ly/getbhce | docker compose -f - up
```
3. Trouvez le mot de passe généré aléatoirement dans la sortie du terminal de Docker Compose.
4. Dans un navigateur, accédez à http://localhost:8080/ui/login. Connectez-vous avec un nom d'utilisateur admin et le mot de passe généré aléatoirement à partir des journaux.

Après cela, vous devrez changer le mot de passe généré aléatoirement et vous aurez la nouvelle interface prête, à partir de laquelle vous pourrez télécharger directement les ingestors.

### SharpHound

Ils ont plusieurs options mais si vous voulez exécuter SharpHound à partir d'un PC joint au domaine, en utilisant votre utilisateur actuel et extraire toutes les informations que vous pouvez faire :
```
./SharpHound.exe --CollectionMethods All
Invoke-BloodHound -CollectionMethod All
```
> Vous pouvez en savoir plus sur la **CollectionMethod** et la session de boucle [ici](https://support.bloodhoundenterprise.io/hc/en-us/articles/17481375424795-All-SharpHound-Community-Edition-Flags-Explained)

Si vous souhaitez exécuter SharpHound en utilisant des informations d'identification différentes, vous pouvez créer une session CMD netonly et exécuter SharpHound à partir de là:
```
runas /netonly /user:domain\user "powershell.exe -exec bypass"
```
[**En savoir plus sur Bloodhound sur ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux)

## Ancienne version de Bloodhound
### Installation

1. Bloodhound

Pour installer l'application de visualisation, vous devrez installer **neo4j** et l'**application Bloodhound**.\
La manière la plus simple de le faire est simplement de faire :
```
apt-get install bloodhound
```
Vous pouvez **télécharger la version communautaire de neo4j** à partir de [ici](https://neo4j.com/download-center/#community).

1. Ingestors

Vous pouvez télécharger les Ingestors depuis :

* https://github.com/BloodHoundAD/SharpHound/releases
* https://github.com/BloodHoundAD/BloodHound/releases
* https://github.com/fox-it/BloodHound.py

1. Apprendre le chemin à partir du graphe

Bloodhound est livré avec diverses requêtes pour mettre en évidence des chemins de compromission sensibles. Il est possible d'ajouter des requêtes personnalisées pour améliorer la recherche et la corrélation entre les objets et plus encore !

Ce dépôt contient une belle collection de requêtes : https://github.com/CompassSecurity/BloodHoundQueries

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
La première fois que vous démarrez cette base de données, vous devrez accéder à [http://localhost:7474/browser/](http://localhost:7474/browser/). Vous devrez utiliser les identifiants par défaut (neo4j:neo4j) et il vous sera **demandé de changer le mot de passe**, donc changez-le et ne l'oubliez pas.

Maintenant, lancez l'application **bloodhound**:
```bash
./BloodHound-linux-x64
#or
bloodhound
```
Vous serez invité à saisir les informations d'identification de la base de données : **neo4j:\<Votre nouveau mot de passe>**

Et BloodHound sera prêt à ingérer des données.

![](<../../.gitbook/assets/image (171) (1).png>)


### **BloodHound Python**

Si vous disposez d'informations d'identification de domaine, vous pouvez exécuter un **ingesteur BloodHound Python depuis n'importe quelle plateforme** afin de ne pas dépendre de Windows.\
Téléchargez-le depuis [https://github.com/fox-it/BloodHound.py](https://github.com/fox-it/BloodHound.py) ou en exécutant `pip3 install bloodhound`
```bash
bloodhound-python -u support -p '#00^BlackKnight' -ns 10.10.10.192 -d blackfield.local -c all
```
Si vous l'exécutez via proxychains, ajoutez `--dns-tcp` pour que la résolution DNS fonctionne à travers le proxy.
```bash
proxychains bloodhound-python -u support -p '#00^BlackKnight' -ns 10.10.10.192 -d blackfield.local -c all --dns-tcp
```
### Python SilentHound

Ce script va **discrètement énumérer un domaine Active Directory via LDAP** en analysant les utilisateurs, les administrateurs, les groupes, etc.

Consultez-le sur [**SilentHound github**](https://github.com/layer8secure/SilentHound).

### RustHound

BloodHound en Rust, [**vérifiez-le ici**](https://github.com/OPENCYBER-FR/RustHound).

## Group3r

[**Group3r**](https://github.com/Group3r/Group3r) **** est un outil pour trouver des **vulnérabilités** dans les **stratégies de groupe** associées à Active Directory. \
Vous devez **exécuter group3r** à partir d'un hôte à l'intérieur du domaine en utilisant **n'importe quel utilisateur de domaine**.
```bash
group3r.exe -f <filepath-name.log>
# -s sends results to stdin
# -f send results to file
```
## PingCastle

****[**PingCastle**](https://www.pingcastle.com/documentation/) **évalue la posture de sécurité d'un environnement AD** et fournit un **rapport** détaillé avec des graphiques.

Pour l'exécuter, vous pouvez lancer le binaire `PingCastle.exe` et il démarrera une **session interactive** présentant un menu d'options. L'option par défaut à utiliser est **`healthcheck`** qui établira une **vue d'ensemble** de **domaine**, et trouvera des **mauvaises configurations** et des **vulnérabilités**.&#x20;
