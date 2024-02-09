# Contraintes de lancement/environnement macOS et cache de confiance

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

* Travaillez-vous dans une **entreprise de cybersécurité**? Voulez-vous voir votre **entreprise annoncée dans HackTricks**? ou voulez-vous avoir accès à la **dernière version du PEASS ou télécharger HackTricks en PDF**? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**dépôt hacktricks**](https://github.com/carlospolop/hacktricks) **et** [**dépôt hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud)
*
* .

</details>

## Informations de base

Les contraintes de lancement dans macOS ont été introduites pour renforcer la sécurité en **régulant comment, qui et d'où un processus peut être initié**. Initiées dans macOS Ventura, elles fournissent un cadre qui catégorise **chaque binaire système en différentes catégories de contraintes**, définies dans le **cache de confiance**, une liste contenant les binaires système et leurs hachages respectifs. Ces contraintes s'étendent à chaque binaire exécutable du système, impliquant un ensemble de **règles** définissant les exigences pour **lancer un binaire particulier**. Les règles englobent les auto-contraintes qu'un binaire doit satisfaire, les contraintes parentales devant être respectées par son processus parent, et les contraintes responsables devant être respectées par d'autres entités pertinentes.

Le mécanisme s'étend aux applications tierces via les **Contraintes d'Environnement**, à partir de macOS Sonoma, permettant aux développeurs de protéger leurs applications en spécifiant un **ensemble de clés et de valeurs pour les contraintes d'environnement**.

Vous définissez les **contraintes de lancement et de bibliothèque** dans des dictionnaires de contraintes que vous enregistrez soit dans des **fichiers de liste de propriétés `launchd`**, soit dans des **fichiers de liste de propriétés séparés** que vous utilisez dans la signature de code.

Il existe 4 types de contraintes :

* **Auto-contraintes** : Contraintes appliquées au binaire **en cours d'exécution**.
* **Processus parent** : Contraintes appliquées au **parent du processus** (par exemple **`launchd`** exécutant un service XP).
* **Contraintes responsables** : Contraintes appliquées au **processus appelant le service** dans une communication XPC.
* **Contraintes de chargement de bibliothèque** : Utilisez des contraintes de chargement de bibliothèque pour décrire sélectivement le code qui peut être chargé.

Ainsi, lorsqu'un processus tente de lancer un autre processus — en appelant `execve(_:_:_:)` ou `posix_spawn(_:_:_:_:_:_:)` — le système d'exploitation vérifie que le fichier exécutable **satisfait** sa **propre contrainte d'auto**. Il vérifie également que le fichier exécutable du **processus parent** **satisfait la contrainte parentale** de l'exécutable, et que le fichier exécutable du **processus responsable** **satisfait la contrainte du processus responsable** de l'exécutable. Si l'une de ces contraintes de lancement n'est pas satisfaite, le système d'exploitation ne lance pas le programme.

Si lors du chargement d'une bibliothèque une partie de la **contrainte de bibliothèque n'est pas vraie**, votre processus **ne charge pas** la bibliothèque.

## Catégories LC

Un LC est composé de **faits** et d'**opérations logiques** (et, ou..) qui combinent des faits.

Les [**faits qu'un LC peut utiliser sont documentés**](https://developer.apple.com/documentation/security/defining\_launch\_environment\_and\_library\_constraints). Par exemple :

* is-init-proc : Une valeur booléenne indiquant si le binaire doit être le processus d'initialisation du système d'exploitation (`launchd`).
* is-sip-protected : Une valeur booléenne indiquant si le binaire doit être un fichier protégé par la Protection de l'Intégrité du Système (SIP).
* `on-authorized-authapfs-volume:` Une valeur booléenne indiquant si le système d'exploitation a chargé le binaire à partir d'un volume APFS autorisé et authentifié.
* `on-authorized-authapfs-volume` : Une valeur booléenne indiquant si le système d'exploitation a chargé le binaire à partir d'un volume APFS autorisé et authentifié.
* Volume Cryptexes
* `on-system-volume:` Une valeur booléenne indiquant si le système d'exploitation a chargé le binaire à partir du volume système actuellement démarré.
* À l'intérieur de /System...
* ...

Lorsqu'un binaire Apple est signé, il **l'assigne à une catégorie LC** à l'intérieur du **cache de confiance**.

* Les **16 catégories LC iOS** ont été [**inversées et documentées ici**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).
* Les **catégories LC actuelles (macOS 14** - Somona) ont été inversées et leurs [**descriptions peuvent être trouvées ici**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).

Par exemple, la Catégorie 1 est :
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
* `(on-authorized-authapfs-volume || on-system-volume)`: Doit être dans le volume Système ou Cryptexes.
* `launch-type == 1`: Doit être un service système (plist dans LaunchDaemons).
* `validation-category == 1`: Un exécutable du système d'exploitation.
* `is-init-proc`: Launchd

### Inversion des catégories LC

Vous avez plus d'informations [**à ce sujet ici**](https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/#reversing-constraints), mais en gros, elles sont définies dans **AMFI (AppleMobileFileIntegrity)**, donc vous devez télécharger le Kit de développement du noyau pour obtenir le **KEXT**. Les symboles commençant par **`kConstraintCategory`** sont les **intéressants**. En les extrayant, vous obtiendrez un flux encodé DER (ASN.1) que vous devrez décoder avec [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) ou la bibliothèque python-asn1 et son script `dump.py`, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master) qui vous donnera une chaîne plus compréhensible.

## Contraintes d'environnement

Ce sont les contraintes de lancement configurées dans les applications **tierces**. Le développeur peut sélectionner les **faits** et les **opérandes logiques à utiliser** dans son application pour restreindre l'accès à celle-ci.

Il est possible d'énumérer les Contraintes d'environnement d'une application avec :
```bash
codesign -d -vvvv app.app
```
## Caches de confiance

Sur **macOS**, il existe quelques caches de confiance :

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

Et sur iOS, cela semble être dans **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**.

{% hint style="warning" %}
Sur macOS fonctionnant sur des appareils Apple Silicon, si un binaire signé par Apple n'est pas dans le cache de confiance, AMFI refusera de le charger.
{% endhint %}

### Énumération des caches de confiance

Les fichiers de cache de confiance précédents sont au format **IMG4** et **IM4P**, IM4P étant la section de charge utile d'un format IMG4.

Vous pouvez utiliser [**pyimg4**](https://github.com/m1stadev/PyIMG4) pour extraire la charge utile des bases de données :

{% code overflow="wrap" %}
```bash
# Installation
python3 -m pip install pyimg4

# Extract payloads data
cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/BaseSystemTrustCache.img4 -p /tmp/BaseSystemTrustCache.im4p
pyimg4 im4p extract -i /tmp/BaseSystemTrustCache.im4p -o /tmp/BaseSystemTrustCache.data

cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/StaticTrustCache.img4 -p /tmp/StaticTrustCache.im4p
pyimg4 im4p extract -i /tmp/StaticTrustCache.im4p -o /tmp/StaticTrustCache.data

pyimg4 im4p extract -i /System/Library/Security/OSLaunchPolicyData -o /tmp/OSLaunchPolicyData.data
```
{% endcode %}

(Une autre option pourrait être d'utiliser l'outil [**img4tool**](https://github.com/tihmstar/img4tool), qui fonctionnera même sur M1 même si la version est ancienne et pour x86\_64 si vous l'installez aux emplacements appropriés).

Maintenant, vous pouvez utiliser l'outil [**trustcache**](https://github.com/CRKatri/trustcache) pour obtenir les informations dans un format lisible :
```bash
# Install
wget https://github.com/CRKatri/trustcache/releases/download/v2.0/trustcache_macos_arm64
sudo mv ./trustcache_macos_arm64 /usr/local/bin/trustcache
xattr -rc /usr/local/bin/trustcache
chmod +x /usr/local/bin/trustcache

# Run
trustcache info /tmp/OSLaunchPolicyData.data | head
trustcache info /tmp/StaticTrustCache.data | head
trustcache info /tmp/BaseSystemTrustCache.data | head

version = 2
uuid = 35EB5284-FD1E-4A5A-9EFB-4F79402BA6C0
entry count = 969
0065fc3204c9f0765049b82022e4aa5b44f3a9c8 [none] [2] [1]
00aab02b28f99a5da9b267910177c09a9bf488a2 [none] [2] [1]
0186a480beeee93050c6c4699520706729b63eff [none] [2] [2]
0191be4c08426793ff3658ee59138e70441fc98a [none] [2] [3]
01b57a71112235fc6241194058cea5c2c7be3eb1 [none] [2] [2]
01e6934cb8833314ea29640c3f633d740fc187f2 [none] [2] [2]
020bf8c388deaef2740d98223f3d2238b08bab56 [none] [2] [3]
```
Le cache de confiance suit la structure suivante, donc la **catégorie LC est la 4ème colonne**
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
Ensuite, vous pourriez utiliser un script tel que [**celui-ci**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) pour extraire des données.

À partir de ces données, vous pouvez vérifier les applications avec une **valeur de contrainte de lancement de `0`**, qui sont celles qui ne sont pas contraintes ([**vérifiez ici**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) pour savoir ce que chaque valeur représente).

## Atténuation des attaques

Les contraintes de lancement auraient atténué plusieurs anciennes attaques en **s'assurant que le processus ne sera pas exécuté dans des conditions inattendues :** par exemple, à partir d'emplacements inattendus ou en étant invoqué par un processus parent inattendu (si seul launchd devrait le lancer).

De plus, les contraintes de lancement **atténuent les attaques de rétrogradation**.

Cependant, elles **ne atténuent pas les abus XPC** courants, les injections de code **Electron** ou les injections de **dylib** sans validation de bibliothèque (à moins que les ID d'équipe pouvant charger des bibliothèques ne soient connus).

### Protection du démon XPC

Dans la version Sonoma, un point notable est la **configuration de responsabilité du service XPC démon**. Le service XPC est responsable de lui-même, contrairement au client connecté qui est responsable. Cela est documenté dans le rapport de rétroaction FB13206884. Cette configuration peut sembler défectueuse, car elle permet certaines interactions avec le service XPC :

- **Lancement du service XPC** : Si on suppose qu'il s'agit d'un bogue, cette configuration ne permet pas d'initier le service XPC via du code malveillant.
- **Connexion à un service actif** : Si le service XPC est déjà en cours d'exécution (éventuellement activé par son application d'origine), il n'y a pas d'obstacles à s'y connecter.

Bien que l'implémentation de contraintes sur le service XPC puisse être bénéfique en **réduisant la fenêtre d'attaque potentielle**, cela ne résout pas le problème principal. Assurer la sécurité du service XPC nécessite fondamentalement de **valider efficacement le client connecté**. C'est la seule méthode pour renforcer la sécurité du service. Il convient également de noter que la configuration de responsabilité mentionnée est actuellement opérationnelle, ce qui peut ne pas correspondre à la conception prévue.

### Protection Electron

Même s'il est nécessaire que l'application soit **ouverte par LaunchService** (dans les contraintes parentales). Cela peut être réalisé en utilisant **`open`** (qui peut définir des variables d'environnement) ou en utilisant l'**API des services de lancement** (où les variables d'environnement peuvent être indiquées).

## Références

* [https://youtu.be/f1HA5QhLQ7Y?t=24146](https://youtu.be/f1HA5QhLQ7Y?t=24146)
* [https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/](https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/)
* [https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
* [https://developer.apple.com/videos/play/wwdc2023/10266/](https://developer.apple.com/videos/play/wwdc2023/10266/)

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Vous voulez voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version du PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud)
*
* .

</details>
