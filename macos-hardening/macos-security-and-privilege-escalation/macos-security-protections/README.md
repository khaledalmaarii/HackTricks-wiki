# Protections de sécurité de macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Gatekeeper

**Gatekeeper** est une fonctionnalité de sécurité développée pour les systèmes d'exploitation Mac, conçue pour garantir que les utilisateurs ne **exécutent que des logiciels de confiance** sur leurs systèmes. Il fonctionne en **validant le logiciel** qu'un utilisateur télécharge et tente d'ouvrir à partir de **sources extérieures à l'App Store**, telles qu'une application, un plug-in ou un package d'installation.

Le mécanisme clé de Gatekeeper réside dans son processus de **vérification**. Il vérifie si le logiciel téléchargé est **signé par un développeur reconnu**, garantissant ainsi l'authenticité du logiciel. De plus, il vérifie si le logiciel est **notarisé par Apple**, confirmant qu'il est exempt de contenu malveillant connu et n'a pas été altéré après la notarisation.

De plus, Gatekeeper renforce le contrôle et la sécurité de l'utilisateur en **demandant aux utilisateurs d'approuver l'ouverture** du logiciel téléchargé pour la première fois. Cette mesure de sécurité aide à empêcher les utilisateurs d'exécuter involontairement un code exécutable potentiellement dangereux qu'ils auraient pu confondre avec un fichier de données inoffensif.

### Signatures d'application

Les signatures d'application, également appelées signatures de code, sont un élément essentiel de l'infrastructure de sécurité d'Apple. Elles sont utilisées pour **vérifier l'identité de l'auteur du logiciel** (le développeur) et pour s'assurer que le code n'a pas été altéré depuis sa dernière signature.

Voici comment cela fonctionne :

1. **Signature de l'application :** Lorsqu'un développeur est prêt à distribuer son application, il **signe l'application à l'aide d'une clé privée**. Cette clé privée est associée à un **certificat qu'Apple délivre au développeur** lorsqu'il s'inscrit au programme de développement Apple. Le processus de signature consiste à créer une empreinte cryptographique de toutes les parties de l'application et à chiffrer cette empreinte avec la clé privée du développeur.
2. **Distribution de l'application :** L'application signée est ensuite distribuée aux utilisateurs avec le certificat du développeur, qui contient la clé publique correspondante.
3. **Vérification de l'application :** Lorsqu'un utilisateur télécharge et tente d'exécuter l'application, son système d'exploitation Mac utilise la clé publique du certificat du développeur pour déchiffrer l'empreinte. Il recalcule ensuite l'empreinte en fonction de l'état actuel de l'application et la compare à l'empreinte déchiffrée. Si elles correspondent, cela signifie que **l'application n'a pas été modifiée** depuis la signature du développeur, et le système autorise l'exécution de l'application.

Les signatures d'application sont une partie essentielle de la technologie Gatekeeper d'Apple. Lorsqu'un utilisateur tente d'**ouvrir une application téléchargée depuis Internet**, Gatekeeper vérifie la signature de l'application. Si elle est signée avec un certificat délivré par Apple à un développeur connu et que le code n'a pas été altéré, Gatekeeper autorise l'exécution de l'application. Sinon, il bloque l'application et alerte l'utilisateur.

À partir de macOS Catalina, **Gatekeeper vérifie également si l'application a été notarisée** par Apple, ajoutant une couche de sécurité supplémentaire. Le processus de notarisation vérifie l'application pour détecter d'éventuels problèmes de sécurité connus et de code malveillant, et si ces vérifications sont réussies, Apple ajoute un ticket à l'application que Gatekeeper peut vérifier.

#### Vérification des signatures

Lors de la vérification d'un **échantillon de logiciel malveillant**, vous devriez toujours **vérifier la signature** du binaire, car le **développeur** qui l'a signé peut déjà être **lié** à un **logiciel malveillant**.
```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo
```
### Notarisation

Le processus de notarisation d'Apple sert de mesure de sécurité supplémentaire pour protéger les utilisateurs des logiciels potentiellement dangereux. Il implique que le développeur soumette son application à l'examen du service de notarisation d'Apple, qui ne doit pas être confondu avec l'examen des applications. Ce service est un système automatisé qui examine le logiciel soumis à la recherche de contenu malveillant et de problèmes éventuels liés à la signature du code.

Si le logiciel passe cette inspection sans soulever de préoccupations, le service de notarisation génère un ticket de notarisation. Le développeur est ensuite tenu de joindre ce ticket à son logiciel, un processus appelé "agrafage". De plus, le ticket de notarisation est également publié en ligne, où Gatekeeper, la technologie de sécurité d'Apple, peut y accéder.

Lors de la première installation ou exécution du logiciel par l'utilisateur, l'existence du ticket de notarisation - qu'il soit agrafé à l'exécutable ou trouvé en ligne - informe Gatekeeper que le logiciel a été notarisé par Apple. En conséquence, Gatekeeper affiche un message descriptif dans la boîte de dialogue de lancement initial, indiquant que le logiciel a été vérifié par Apple pour détecter tout contenu malveillant. Ce processus renforce ainsi la confiance de l'utilisateur dans la sécurité du logiciel qu'il installe ou exécute sur son système.

### Énumération de GateKeeper

GateKeeper est à la fois plusieurs composants de sécurité qui empêchent l'exécution d'applications non fiables et l'un des composants.

Il est possible de voir l'état de GateKeeper avec :
```bash
# Check the status
spctl --status
```
{% hint style="danger" %}
Notez que les vérifications de signature de GateKeeper ne sont effectuées que sur les fichiers avec l'attribut Quarantine, et non sur tous les fichiers.
{% endhint %}

GateKeeper vérifiera si, selon les préférences et la signature, un binaire peut être exécuté :

<figure><img src="../../../.gitbook/assets/image (678).png" alt=""><figcaption></figcaption></figure>

La base de données qui conserve cette configuration est située dans **`/var/db/SystemPolicy`**. Vous pouvez vérifier cette base de données en tant que root avec la commande suivante :
```bash
# Open database
sqlite3 /var/db/SystemPolicy

# Get allowed rules
SELECT requirement,allow,disabled,label from authority where label != 'GKE' and disabled=0;
requirement|allow|disabled|label
anchor apple generic and certificate 1[subject.CN] = "Apple Software Update Certification Authority"|1|0|Apple Installer
anchor apple|1|0|Apple System
anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists|1|0|Mac App Store
anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and (certificate leaf[field.1.2.840.113635.100.6.1.14] or certificate leaf[field.1.2.840.113635.100.6.1.13]) and notarized|1|0|Notarized Developer ID
[...]
```
Notez comment la première règle se termine par "**App Store**" et la deuxième par "**Developer ID**" et que dans l'image précédente, il était **activé pour exécuter des applications provenant de l'App Store et de développeurs identifiés**.\
Si vous **modifiez** ce paramètre en App Store, les règles "**Notarized Developer ID**" disparaîtront.

Il existe également des milliers de règles de **type GKE** :
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Ce sont des hachages provenant de **`/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`, `/var/db/gke.bundle/Contents/Resources/gk.db`** et **`/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`**

Les options **`--master-disable`** et **`--global-disable`** de **`spctl`** désactiveront complètement ces vérifications de signature:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
Lorsqu'il est complètement activé, une nouvelle option apparaîtra :

<figure><img src="../../../.gitbook/assets/image (679).png" alt=""><figcaption></figcaption></figure>

Il est possible de **vérifier si une application sera autorisée par GateKeeper** avec :
```bash
spctl --assess -v /Applications/App.app
```
Il est possible d'ajouter de nouvelles règles dans GateKeeper pour autoriser l'exécution de certaines applications avec:
```bash
# Check if allowed - nop
spctl --assess -v /Applications/App.app
/Applications/App.app: rejected
source=no usable signature

# Add a label and allow this label in GateKeeper
sudo spctl --add --label "whitelist" /Applications/App.app
sudo spctl --enable --label "whitelist"

# Check again - yep
spctl --assess -v /Applications/App.app
/Applications/App.app: accepted
```
### Fichiers en quarantaine

Lors du **téléchargement** d'une application ou d'un fichier, certaines applications macOS telles que les navigateurs web ou les clients de messagerie **attachent un attribut de fichier étendu**, communément appelé "**drapeau de quarantaine**", au fichier téléchargé. Cet attribut agit comme une mesure de sécurité pour **marquer le fichier** comme provenant d'une source non fiable (Internet) et potentiellement porteur de risques. Cependant, toutes les applications n'attachent pas cet attribut, par exemple, les logiciels clients BitTorrent courants contournent généralement ce processus.

**La présence d'un drapeau de quarantaine signale la fonctionnalité de sécurité Gatekeeper de macOS lorsque l'utilisateur tente d'exécuter le fichier**.

Dans le cas où le **drapeau de quarantaine n'est pas présent** (comme pour les fichiers téléchargés via certains clients BitTorrent), les **vérifications de Gatekeeper peuvent ne pas être effectuées**. Par conséquent, les utilisateurs doivent faire preuve de prudence lors de l'ouverture de fichiers téléchargés à partir de sources moins sécurisées ou inconnues.

{% hint style="info" %}
**Vérifier** la **validité** des signatures de code est un processus **gourmand en ressources** qui comprend la génération de **hachages** cryptographiques du code et de toutes ses ressources incluses. De plus, la vérification de la validité du certificat implique une **vérification en ligne** auprès des serveurs d'Apple pour voir s'il a été révoqué après sa délivrance. Pour ces raisons, une vérification complète de la signature du code et de la notarisation est **impraticable à exécuter à chaque lancement d'une application**.

Par conséquent, ces vérifications sont **uniquement effectuées lors de l'exécution d'applications avec l'attribut de quarantaine**.
{% endhint %}

{% hint style="warning" %}
Cet attribut doit être **défini par l'application créant/téléchargeant** le fichier.

Cependant, les fichiers qui sont sandboxés auront cet attribut défini pour chaque fichier qu'ils créent. Et les applications non sandboxées peuvent le définir elles-mêmes, ou spécifier la clé [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information\_property\_list/lsfilequarantineenabled?language=objc) dans le fichier **Info.plist**, ce qui amènera le système à définir l'attribut étendu `com.apple.quarantine` sur les fichiers créés.
{% endhint %}

Il est possible de **vérifier son statut et d'activer/désactiver** (nécessite les droits d'administrateur) avec :
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Vous pouvez également **vérifier si un fichier possède l'attribut étendu de quarantaine** avec la commande suivante :
```bash
xattr portada.png
com.apple.macl
com.apple.quarantine
```
Vérifiez la **valeur** des **attributs étendus** et découvrez l'application qui a écrit l'attribut de mise en quarantaine avec :
```bash
xattr -l portada.png
com.apple.macl:
00000000  03 00 53 DA 55 1B AE 4C 4E 88 9D CA B7 5C 50 F3  |..S.U..LN.....P.|
00000010  16 94 03 00 27 63 64 97 98 FB 4F 02 84 F3 D0 DB  |....'cd...O.....|
00000020  89 53 C3 FC 03 00 27 63 64 97 98 FB 4F 02 84 F3  |.S....'cd...O...|
00000030  D0 DB 89 53 C3 FC 00 00 00 00 00 00 00 00 00 00  |...S............|
00000040  00 00 00 00 00 00 00 00                          |........|
00000048
com.apple.quarantine: 00C1;607842eb;Brave;F643CD5F-6071-46AB-83AB-390BA944DEC5
# 00c1 -- It has been allowed to eexcute this file
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```
Et **supprimez** cet attribut avec :
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
Et trouvez tous les fichiers mis en quarantaine avec :

{% code overflow="wrap" %}
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
{% endcode %}

Les informations de quarantaine sont également stockées dans une base de données centrale gérée par LaunchServices dans **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**.

### XProtect

XProtect est une fonctionnalité **anti-malware** intégrée à macOS. XProtect **vérifie toute application lors de son premier lancement ou de sa modification par rapport à sa base de données** de logiciels malveillants connus et de types de fichiers non sécurisés. Lorsque vous téléchargez un fichier via certaines applications, telles que Safari, Mail ou Messages, XProtect analyse automatiquement le fichier. S'il correspond à un logiciel malveillant connu dans sa base de données, XProtect **empêche l'exécution du fichier** et vous alerte de la menace.

La base de données XProtect est **régulièrement mise à jour** par Apple avec de nouvelles définitions de logiciels malveillants, et ces mises à jour sont automatiquement téléchargées et installées sur votre Mac. Cela garantit que XProtect est toujours à jour avec les dernières menaces connues.

Cependant, il est important de noter que **XProtect n'est pas une solution antivirus complète**. Il ne vérifie que pour une liste spécifique de menaces connues et ne réalise pas de numérisation en temps réel comme la plupart des logiciels antivirus.

Vous pouvez obtenir des informations sur la dernière mise à jour de XProtect en exécutant :

{% code overflow="wrap" %}
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
{% endcode %}

XProtect est situé dans un emplacement protégé par SIP à **/Library/Apple/System/Library/CoreServices/XProtect.bundle** et à l'intérieur du bundle, vous pouvez trouver les informations utilisées par XProtect :

* **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`** : Autorise le code avec ces cdhashes à utiliser des autorisations héritées.
* **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`** : Liste des plugins et extensions qui sont interdits de chargement via BundleID et TeamID ou indiquant une version minimale.
* **`XProtect.bundle/Contents/Resources/XProtect.yara`** : Règles Yara pour détecter les logiciels malveillants.
* **`XProtect.bundle/Contents/Resources/gk.db`** : Base de données SQLite3 avec les hachages des applications bloquées et des TeamIDs.

Notez qu'il y a une autre application dans **`/Library/Apple/System/Library/CoreServices/XProtect.app`** liée à XProtect qui n'est pas impliquée lorsqu'une application est exécutée.

## MRT - Outil de suppression de logiciels malveillants

L'outil de suppression de logiciels malveillants (MRT) est une autre partie de l'infrastructure de sécurité de macOS. Comme son nom l'indique, la principale fonction de MRT est de **supprimer les logiciels malveillants connus des systèmes infectés**.

Une fois qu'un logiciel malveillant est détecté sur un Mac (soit par XProtect, soit par d'autres moyens), MRT peut être utilisé pour **supprimer automatiquement le logiciel malveillant**. MRT fonctionne silencieusement en arrière-plan et s'exécute généralement chaque fois que le système est mis à jour ou lorsqu'une nouvelle définition de logiciel malveillant est téléchargée (il semble que les règles que MRT utilise pour détecter les logiciels malveillants se trouvent à l'intérieur du binaire).

Bien que XProtect et MRT fassent tous deux partie des mesures de sécurité de macOS, ils remplissent des fonctions différentes :

* **XProtect** est un outil préventif. Il **vérifie les fichiers lorsqu'ils sont téléchargés** (via certaines applications), et s'il détecte des types de logiciels malveillants connus, il **empêche l'ouverture du fichier**, empêchant ainsi le logiciel malveillant d'infecter votre système dès le départ.
* **MRT**, en revanche, est un outil **réactif**. Il intervient après la détection d'un logiciel malveillant sur un système, dans le but de supprimer le logiciel incriminé pour nettoyer le système.

L'application MRT se trouve dans **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Limitations des processus

### SIP - Protection de l'intégrité du système

{% content-ref url="macos-sip.md" %}
[macos-sip.md](macos-sip.md)
{% endcontent-ref %}

### Bac à sable

Le bac à sable de macOS **limite les applications** s'exécutant à l'intérieur du bac à sable aux **actions autorisées spécifiées dans le profil du bac à sable** avec lequel l'application s'exécute. Cela permet de s'assurer que **l'application n'accède qu'aux ressources attendues**.

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - **Transparence, Consentement et Contrôle**

**TCC (Transparence, Consentement et Contrôle)** est un mécanisme de macOS visant à **limiter et contrôler l'accès des applications à certaines fonctionnalités**, généralement dans une perspective de confidentialité. Cela peut inclure des services de localisation, des contacts, des photos, un microphone, une caméra, l'accessibilité, l'accès complet au disque et bien d'autres.

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

## Cache de confiance

Le cache de confiance d'Apple macOS, parfois appelé cache AMFI (Apple Mobile File Integrity), est un mécanisme de sécurité de macOS conçu pour **empêcher l'exécution de logiciels non autorisés ou malveillants**. Essentiellement, il s'agit d'une liste de hachages cryptographiques que le système d'exploitation utilise pour **vérifier l'intégrité et l'authenticité du logiciel**.

Lorsqu'une application ou un fichier exécutable tente de s'exécuter sur macOS, le système d'exploitation vérifie le cache de confiance AMFI. Si le **hachage du fichier est trouvé dans le cache de confiance**, le système **autorise** le programme à s'exécuter car il le reconnaît comme étant de confiance.

## Contraintes de lancement

Il contrôle d'où et ce qui peut lancer un binaire signé par Apple :

* Vous ne pouvez pas lancer une application directement si elle doit être exécutée par launchd.
* Vous ne pouvez pas exécuter une application en dehors de l'emplacement de confiance (comme /System/).

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Vous travaillez dans une **entreprise de cybersécurité** ? Vous souhaitez voir votre **entreprise annoncée dans HackTricks** ? ou souhaitez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
