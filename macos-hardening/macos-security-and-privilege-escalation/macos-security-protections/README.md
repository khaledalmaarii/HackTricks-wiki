## Gatekeeper

**Gatekeeper** est une fonctionnalité de sécurité développée pour les systèmes d'exploitation Mac, conçue pour garantir que les utilisateurs ne **lancent que des logiciels de confiance** sur leurs systèmes. Elle fonctionne en **validant les logiciels** qu'un utilisateur télécharge et tente d'ouvrir à partir de **sources en dehors de l'App Store**, telles qu'une application, un plug-in ou un package d'installation.

Le mécanisme clé de Gatekeeper réside dans son processus de **vérification**. Il vérifie si le logiciel téléchargé est **signé par un développeur reconnu**, garantissant l'authenticité du logiciel. De plus, il vérifie si le logiciel est **notarisé par Apple**, confirmant qu'il est exempt de contenu malveillant connu et qu'il n'a pas été altéré après la notarisation.

De plus, Gatekeeper renforce le contrôle et la sécurité de l'utilisateur en **demandant aux utilisateurs d'approuver l'ouverture** des logiciels téléchargés pour la première fois. Cette mesure de sécurité aide à empêcher les utilisateurs de lancer involontairement un code exécutable potentiellement dangereux qu'ils auraient pu confondre avec un fichier de données inoffensif.
```bash
# Check the status
spctl --status
# Enable Gatekeeper
sudo spctl --master-enable
# Disable Gatekeeper
sudo spctl --master-disable
```
### Signatures d'application

Les signatures d'application, également connues sous le nom de signatures de code, sont un élément critique de l'infrastructure de sécurité d'Apple. Elles sont utilisées pour **vérifier l'identité de l'auteur du logiciel** (le développeur) et pour s'assurer que le code n'a pas été altéré depuis la dernière signature.

Voici comment cela fonctionne :

1. **Signature de l'application :** Lorsqu'un développeur est prêt à distribuer son application, il **signe l'application à l'aide d'une clé privée**. Cette clé privée est associée à un **certificat qu'Apple délivre au développeur** lorsqu'il s'inscrit au programme de développement Apple. Le processus de signature consiste à créer un hachage cryptographique de toutes les parties de l'application et à chiffrer ce hachage avec la clé privée du développeur.
2. **Distribution de l'application :** L'application signée est ensuite distribuée aux utilisateurs avec le certificat du développeur, qui contient la clé publique correspondante.
3. **Vérification de l'application :** Lorsqu'un utilisateur télécharge et tente d'exécuter l'application, son système d'exploitation Mac utilise la clé publique du certificat du développeur pour déchiffrer le hachage. Il recalcule ensuite le hachage en fonction de l'état actuel de l'application et le compare à celui déchiffré. S'ils correspondent, cela signifie que **l'application n'a pas été modifiée** depuis la signature du développeur, et le système autorise l'exécution de l'application.

Les signatures d'application sont une partie essentielle de la technologie Gatekeeper d'Apple. Lorsqu'un utilisateur tente d'**ouvrir une application téléchargée depuis Internet**, Gatekeeper vérifie la signature de l'application. Si elle est signée avec un certificat délivré par Apple à un développeur connu et que le code n'a pas été altéré, Gatekeeper autorise l'exécution de l'application. Sinon, il bloque l'application et alerte l'utilisateur.

À partir de macOS Catalina, **Gatekeeper vérifie également si l'application a été notarisée** par Apple, ajoutant une couche de sécurité supplémentaire. Le processus de notarisation vérifie l'application pour détecter les problèmes de sécurité connus et le code malveillant, et si ces vérifications sont réussies, Apple ajoute un ticket à l'application que Gatekeeper peut vérifier.

#### Vérification des signatures

Lors de la vérification d'un **échantillon de logiciel malveillant**, vous devriez toujours **vérifier la signature** du binaire car le **développeur** qui l'a signé peut déjà être **lié** à un **logiciel malveillant**.
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

Le processus de notarisation d'Apple sert de mesure de sécurité supplémentaire pour protéger les utilisateurs des logiciels potentiellement dangereux. Il implique que le développeur soumette son application à l'examen du service de notarisation d'Apple, qui ne doit pas être confondu avec l'examen de l'application. Ce service est un système automatisé qui examine le logiciel soumis à la recherche de contenu malveillant et de tout problème potentiel de signature de code.

Si le logiciel passe cette inspection sans soulever de préoccupations, le service de notarisation génère un ticket de notarisation. Le développeur est alors tenu de joindre ce ticket à son logiciel, un processus appelé "agrafage". De plus, le ticket de notarisation est également publié en ligne où Gatekeeper, la technologie de sécurité d'Apple, peut y accéder.

Lors de la première installation ou exécution du logiciel par l'utilisateur, l'existence du ticket de notarisation - qu'il soit agrafé à l'exécutable ou trouvé en ligne - informe Gatekeeper que le logiciel a été notarisé par Apple. Par conséquent, Gatekeeper affiche un message descriptif dans la boîte de dialogue de lancement initial, indiquant que le logiciel a été vérifié pour la présence de contenu malveillant par Apple. Ce processus renforce ainsi la confiance de l'utilisateur dans la sécurité du logiciel qu'il installe ou exécute sur son système.

### Fichiers en quarantaine

Lors du téléchargement d'une application ou d'un fichier, des applications macOS spécifiques telles que les navigateurs Web ou les clients de messagerie électronique attachent un attribut de fichier étendu, communément appelé "drapeau de quarantaine", au fichier téléchargé. Cet attribut sert de mesure de sécurité pour marquer le fichier comme provenant d'une source non fiable (Internet) et potentiellement risqué. Cependant, toutes les applications n'attachent pas cet attribut, par exemple, les logiciels clients BitTorrent courants contournent généralement ce processus.

La présence d'un drapeau de quarantaine signale la fonctionnalité de sécurité Gatekeeper de macOS lorsque l'utilisateur tente d'exécuter le fichier.

Dans le cas où le drapeau de quarantaine n'est pas présent (comme pour les fichiers téléchargés via certains clients BitTorrent), les vérifications de Gatekeeper peuvent ne pas être effectuées. Par conséquent, les utilisateurs doivent faire preuve de prudence lorsqu'ils ouvrent des fichiers téléchargés à partir de sources moins sécurisées ou inconnues.

{% hint style="info" %}
La vérification de la validité des signatures de code est un processus intensif en ressources qui comprend la génération de hachages cryptographiques du code et de toutes ses ressources groupées. De plus, la vérification de la validité du certificat implique une vérification en ligne auprès des serveurs d'Apple pour voir s'il a été révoqué après sa délivrance. Pour ces raisons, une vérification complète de la signature de code et de la notarisation est impraticable à exécuter à chaque fois qu'une application est lancée.

Par conséquent, ces vérifications ne sont effectuées que lors de l'exécution d'applications avec l'attribut en quarantaine.
{% endhint %}

{% hint style="warning" %}
Notez que Safari et d'autres navigateurs Web et applications sont ceux qui doivent marquer les fichiers téléchargés.

De plus, les fichiers créés par des processus sandboxés se voient également attribuer cet attribut pour empêcher les évasions de sandbox.
{% endhint %}

Il est possible de vérifier son statut et d'activer/désactiver (nécessite des privilèges d'administrateur) avec:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Vous pouvez également **vérifier si un fichier possède l'attribut étendu de quarantaine** avec:
```bash
xattr portada.png
com.apple.macl
com.apple.quarantine
```
Vérifiez la **valeur** des **attributs étendus** avec:
```bash
xattr -l portada.png
com.apple.macl:
00000000  03 00 53 DA 55 1B AE 4C 4E 88 9D CA B7 5C 50 F3  |..S.U..LN.....P.|
00000010  16 94 03 00 27 63 64 97 98 FB 4F 02 84 F3 D0 DB  |....'cd...O.....|
00000020  89 53 C3 FC 03 00 27 63 64 97 98 FB 4F 02 84 F3  |.S....'cd...O...|
00000030  D0 DB 89 53 C3 FC 00 00 00 00 00 00 00 00 00 00  |...S............|
00000040  00 00 00 00 00 00 00 00                          |........|
00000048
com.apple.quarantine: 0081;607842eb;Brave;F643CD5F-6071-46AB-83AB-390BA944DEC5
```
Et **supprimez** cet attribut avec:
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

## XProtect

XProtect est une fonctionnalité **anti-malware** intégrée à macOS. Elle fait partie du système de sécurité d'Apple qui fonctionne silencieusement en arrière-plan pour protéger votre Mac contre les malwares connus et les plug-ins malveillants.

XProtect fonctionne en **vérifiant tous les fichiers téléchargés par rapport à sa base de données** de malwares connus et de types de fichiers non sécurisés. Lorsque vous téléchargez un fichier via certaines applications, telles que Safari, Mail ou Messages, XProtect analyse automatiquement le fichier. S'il correspond à un malware connu dans sa base de données, XProtect **empêchera le fichier de s'exécuter** et vous alertera de la menace.

La base de données XProtect est **régulièrement mise à jour** par Apple avec de nouvelles définitions de malwares, et ces mises à jour sont automatiquement téléchargées et installées sur votre Mac. Cela garantit que XProtect est toujours à jour avec les dernières menaces connues.

Cependant, il convient de noter que **XProtect n'est pas une solution antivirus complète**. Il ne vérifie que pour une liste spécifique de menaces connues et ne réalise pas de numérisation à l'accès comme la plupart des logiciels antivirus. Par conséquent, bien que XProtect offre une couche de protection contre les malwares connus, il est toujours recommandé de faire preuve de prudence lors du téléchargement de fichiers depuis Internet ou de l'ouverture de pièces jointes d'e-mail.

Vous pouvez obtenir des informations sur la dernière mise à jour de XProtect en cours d'exécution :

{% code overflow="wrap" %}
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
{% endcode %}

## MRT - Outil de suppression de logiciels malveillants

L'outil de suppression de logiciels malveillants (MRT) est une autre partie de l'infrastructure de sécurité de macOS. Comme son nom l'indique, la fonction principale de MRT est de **supprimer les logiciels malveillants connus des systèmes infectés**.

Une fois que des logiciels malveillants sont détectés sur un Mac (soit par XProtect, soit par d'autres moyens), MRT peut être utilisé pour **supprimer automatiquement les logiciels malveillants**. MRT fonctionne silencieusement en arrière-plan et s'exécute généralement chaque fois que le système est mis à jour ou lorsqu'une nouvelle définition de logiciel malveillant est téléchargée.

Bien que XProtect et MRT fassent tous deux partie des mesures de sécurité de macOS, ils remplissent des fonctions différentes :

* **XProtect** est un outil préventif. Il **vérifie les fichiers lorsqu'ils sont téléchargés** (via certaines applications), et s'il détecte des types de logiciels malveillants connus, il **empêche l'ouverture du fichier**, empêchant ainsi le logiciel malveillant d'infecter votre système en premier lieu.
* **MRT**, en revanche, est un **outil réactif**. Il fonctionne après la détection de logiciels malveillants sur un système, dans le but de supprimer le logiciel incriminé pour nettoyer le système.

## Limitation des processus

### SIP - Protection de l'intégrité du système

### Bac à sable

Le bac à sable de MacOS **limite les applications** s'exécutant à l'intérieur du bac à sable aux **actions autorisées spécifiées dans le profil de bac à sable** avec lequel l'application s'exécute. Cela aide à garantir que **l'application n'accédera qu'aux ressources attendues**.

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - Transparence, consentement et contrôle

**TCC (Transparence, consentement et contrôle)** est un mécanisme de macOS pour **limiter et contrôler l'accès des applications à certaines fonctionnalités**, généralement d'un point de vue de la confidentialité. Cela peut inclure des choses telles que les services de localisation, les contacts, les photos, le microphone, la caméra, l'accessibilité, l'accès complet au disque et bien plus encore.

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
