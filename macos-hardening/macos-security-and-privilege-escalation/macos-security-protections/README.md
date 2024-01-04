# Protections de sécurité macOS

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Gatekeeper

Gatekeeper est généralement utilisé pour désigner la combinaison de **Quarantine + Gatekeeper + XProtect**, 3 modules de sécurité macOS qui tentent de **prévenir l'exécution de logiciels potentiellement malveillants téléchargés**.

Plus d'informations dans :

{% content-ref url="macos-gatekeeper.md" %}
[macos-gatekeeper.md](macos-gatekeeper.md)
{% endcontent-ref %}

## Limitations des processus

### SIP - System Integrity Protection

{% content-ref url="macos-sip.md" %}
[macos-sip.md](macos-sip.md)
{% endcontent-ref %}

### Sandbox

Le Sandbox macOS **limite les applications** s'exécutant dans le sandbox aux **actions autorisées spécifiées dans le profil Sandbox** avec lequel l'application fonctionne. Cela aide à garantir que **l'application n'accédera qu'aux ressources attendues**.

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - **Transparence, Consentement et Contrôle**

**TCC (Transparence, Consentement et Contrôle)** est un mécanisme dans macOS pour **limiter et contrôler l'accès des applications à certaines fonctionnalités**, généralement d'un point de vue de la vie privée. Cela peut inclure des éléments tels que les services de localisation, les contacts, les photos, le microphone, la caméra, l'accessibilité, l'accès complet au disque et bien d'autres.

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

### Contraintes de lancement/environnement & Trust Cache

Les contraintes de lancement dans macOS sont une fonctionnalité de sécurité pour **réguler l'initiation des processus** en définissant **qui peut lancer** un processus, **comment**, et **d'où**. Introduites dans macOS Ventura, elles catégorisent les binaires système en catégories de contraintes au sein d'un **trust cache**. Chaque binaire exécutable a des **règles** définies pour son **lancement**, y compris les contraintes **self**, **parent** et **responsible**. Étendues aux applications tierces sous forme de Contraintes d'**Environnement** dans macOS Sonoma, ces fonctionnalités aident à atténuer les exploitations potentielles du système en gouvernant les conditions de lancement des processus.

{% content-ref url="macos-launch-environment-constraints.md" %}
[macos-launch-environment-constraints.md](macos-launch-environment-constraints.md)
{% endcontent-ref %}

## MRT - Outil de suppression de logiciels malveillants

L'Outil de suppression de logiciels malveillants (MRT) est une autre partie de l'infrastructure de sécurité de macOS. Comme son nom l'indique, la fonction principale de MRT est de **supprimer les logiciels malveillants connus des systèmes infectés**.

Une fois qu'un logiciel malveillant est détecté sur un Mac (soit par XProtect, soit par d'autres moyens), MRT peut être utilisé pour **supprimer automatiquement le logiciel malveillant**. MRT fonctionne silencieusement en arrière-plan et s'exécute généralement chaque fois que le système est mis à jour ou lorsqu'une nouvelle définition de logiciel malveillant est téléchargée (il semble que les règles que MRT doit détecter les logiciels malveillants sont à l'intérieur du binaire).

Bien que XProtect et MRT fassent partie des mesures de sécurité de macOS, ils remplissent des fonctions différentes :

* **XProtect** est un outil préventif. Il **vérifie les fichiers au moment de leur téléchargement** (via certaines applications), et s'il détecte un type de logiciel malveillant connu, il **empêche l'ouverture du fichier**, empêchant ainsi le logiciel malveillant d'infecter votre système en premier lieu.
* **MRT**, en revanche, est un outil **réactif**. Il opère après qu'un logiciel malveillant a été détecté sur un système, avec pour objectif de supprimer le logiciel offensant pour nettoyer le système.

L'application MRT se trouve dans **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Gestion des tâches en arrière-plan

**macOS** **alerte** maintenant chaque fois qu'un outil utilise une technique bien connue pour **persister l'exécution du code** (comme les éléments de connexion, les Daemons...), afin que l'utilisateur sache mieux **quel logiciel persiste**.

<figure><img src="../../../.gitbook/assets/image (711).png" alt=""><figcaption></figcaption></figure>

Cela fonctionne avec un **daemon** situé dans `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` et l'**agent** dans `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`

La manière dont **`backgroundtaskmanagementd`** sait que quelque chose est installé dans un dossier persistant est en **obtenant les FSEvents** et en créant des **gestionnaires** pour ceux-ci.

De plus, il existe un fichier plist qui contient **des applications bien connues** qui persistent fréquemment maintenues par Apple situé dans : `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`
```json
[...]
"us.zoom.ZoomDaemon" => {
"AssociatedBundleIdentifiers" => [
0 => "us.zoom.xos"
]
"Attribution" => "Zoom"
"Program" => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
"ProgramArguments" => [
0 => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
]
"TeamIdentifier" => "BJ4HAAB9B3"
}
[...]
```
### Énumération

Il est possible d'**énumérer tous** les éléments d'arrière-plan configurés en exécutant l'outil en ligne de commande Apple :
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
De plus, il est également possible de lister ces informations avec [**DumpBTM**](https://github.com/objective-see/DumpBTM).
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
### Manipulation du BTM

Lorsqu'une nouvelle persistance est trouvée, un événement de type **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** est généré. Ainsi, toute méthode pour **empêcher** cet **événement** d'être envoyé ou l'**agent d'alerter** l'utilisateur aidera un attaquant à _**contourner**_ le BTM.

* **Réinitialisation de la base de données** : Exécuter la commande suivante réinitialisera la base de données (elle devrait se reconstruire à partir de zéro), cependant, pour une raison quelconque, après l'exécution de celle-ci, **aucune nouvelle persistance ne sera signalée jusqu'au redémarrage du système**.
* Les droits de **root** sont requis.
```bash
# Reset the database
sfltool resettbtm
```
* **Arrêter l'Agent** : Il est possible d'envoyer un signal d'arrêt à l'agent afin qu'il **n'alerte pas l'utilisateur** lorsque de nouvelles détections sont trouvées.
```bash
# Get PID
pgrep BackgroundTaskManagementAgent
1011

# Stop it
kill -SIGSTOP 1011

# Check it's stopped (a T means it's stopped)
ps -o state 1011
T
```
* **Bug** : Si le **processus qui a créé la persistance se termine rapidement juste après**, le démon essaiera d'**obtenir des informations** à son sujet, **échouera**, et **ne pourra pas envoyer l'événement** indiquant qu'une nouvelle chose persiste.

Références et **plus d'informations sur BTM** :

* [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
* [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
* [https://support.apple.com/fr-fr/guide/deployment/depdca572563/web](https://support.apple.com/fr-fr/guide/deployment/depdca572563/web)

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> !</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
