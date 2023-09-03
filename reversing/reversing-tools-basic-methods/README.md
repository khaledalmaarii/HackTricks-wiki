# Outils de rétro-ingénierie et méthodes de base

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trouvez les vulnérabilités les plus importantes afin de pouvoir les corriger plus rapidement. Intruder suit votre surface d'attaque, effectue des analyses de menace proactives, trouve des problèmes dans l'ensemble de votre pile technologique, des API aux applications web et aux systèmes cloud. [**Essayez-le gratuitement**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) dès aujourd'hui.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Outils de rétro-ingénierie basés sur ImGui

Logiciel :

* ReverseKit : [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Décompilateur Wasm / Compilateur Wat

En ligne :

* Utilisez [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) pour **décompiler** du wasm (binaire) en wat (texte clair)
* Utilisez [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) pour **compiler** du wat en wasm
* Vous pouvez également essayer d'utiliser [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) pour décompiler

Logiciel :

* [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
* [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Décompilateur .Net

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek est un décompilateur qui **décompile et examine plusieurs formats**, y compris les **bibliothèques** (.dll), les fichiers de **métadonnées Windows** (.winmd) et les **exécutables** (.exe). Une fois décompilée, une assembly peut être enregistrée en tant que projet Visual Studio (.csproj).

Le mérite ici est que si un code source perdu nécessite une restauration à partir d'une assembly héritée, cette action peut faire gagner du temps. De plus, dotPeek offre une navigation pratique dans le code décompilé, ce qui en fait l'un des outils parfaits pour l'analyse des algorithmes Xamarin.

### [.Net Reflector](https://www.red-gate.com/products/reflector/)

Avec un modèle d'extension complet et une API qui étend l'outil pour répondre à vos besoins exacts, .NET reflector fait gagner du temps et simplifie le développement. Jetons un coup d'œil à la pléthore de services d'ingénierie inverse que cet outil offre :

* Fournit un aperçu de la façon dont les données circulent à travers une bibliothèque ou un composant
* Fournit un aperçu de la mise en œuvre et de l'utilisation des langages et frameworks .NET
* Trouve des fonctionnalités non documentées et non exposées pour tirer le meilleur parti des API et des technologies utilisées.
* Trouve les dépendances et les différentes assemblies
* Localise l'emplacement exact des erreurs dans votre code, les composants tiers et les bibliothèques.
* Débogue le code source de tout le code .NET avec lequel vous travaillez.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Plugin ILSpy pour Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode) : Vous pouvez l'avoir sur n'importe quel système d'exploitation (vous pouvez l'installer directement depuis VSCode, pas besoin de télécharger le git. Cliquez sur **Extensions** et **recherchez ILSpy**).\
Si vous avez besoin de **décompiler**, **modifier** et **recompiler** à nouveau, vous pouvez utiliser : [**https://github.com/0xd4d/dnSpy/releases**](https://github.com/0xd4d/dnSpy/releases) (**Clic droit -> Modifier la méthode** pour changer quelque chose à l'intérieur d'une fonction).\
Vous pouvez également essayer [https://www.jetbrains.com/es-es/decompiler/](https://www.jetbrains.com/es-es/decompiler/)

### Journalisation DNSpy

Pour faire en sorte que **DNSpy enregistre certaines informations dans un fichier**, vous pouvez utiliser ces lignes de code .Net :
```bash
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### Débogage avec DNSpy

Pour déboguer du code à l'aide de DNSpy, vous devez :

Tout d'abord, modifier les **attributs de l'assembly** liés au **débogage** :

![](<../../.gitbook/assets/image (278).png>)
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
À:

# Reverse Engineering Tools: Basic Methods

Reverse engineering is the process of analyzing a software program to understand its structure, functionality, and behavior. Reverse engineering tools are essential for this process, as they help in dissecting and understanding the inner workings of a program.

In this guide, we will explore some basic methods and tools used in reverse engineering. These tools are commonly used by hackers, security researchers, and software developers to analyze and modify software.

## Disassemblers

A disassembler is a tool that converts machine code into assembly code. It allows you to view the low-level instructions of a program, making it easier to understand how the program works. Some popular disassemblers include IDA Pro, Ghidra, and Radare2.

## Debuggers

Debuggers are tools that allow you to analyze and manipulate the execution of a program. They provide features like breakpoints, stepping through code, and inspecting variables. Popular debuggers include OllyDbg, GDB, and WinDbg.

## Decompilers

Decompilers are tools that convert compiled machine code back into a high-level programming language. They can be useful when you want to understand the logic of a program or modify its behavior. Some popular decompilers include IDA Pro, Ghidra, and RetDec.

## Hex Editors

Hex editors are tools that allow you to view and edit binary files at the hexadecimal level. They are useful for analyzing and modifying the raw data of a program. Some popular hex editors include HxD, Hex Fiend, and Bless.

## Packers and Unpackers

Packers are tools used to compress and encrypt executable files. They make it harder to analyze and modify the program. Unpackers, on the other hand, are tools used to reverse the packing process and restore the original executable. Some popular packers and unpackers include UPX, Themida, and PEiD.

## Conclusion

These are just some of the basic methods and tools used in reverse engineering. By using these tools, you can gain a deeper understanding of how software works and identify vulnerabilities that can be exploited. However, it's important to note that reverse engineering should only be done legally and ethically, with proper authorization.
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
Et cliquez sur **compiler** :

![](<../../.gitbook/assets/image (314) (1) (1).png>)

Ensuite, enregistrez le nouveau fichier sur _**Fichier >> Enregistrer le module...**_ :

![](<../../.gitbook/assets/image (279).png>)

Ceci est nécessaire car si vous ne le faites pas, lors de l'**exécution**, plusieurs **optimisations** seront appliquées au code et il se pourrait que lors du débogage, un **point d'arrêt ne soit jamais atteint** ou que certaines **variables n'existent pas**.

Ensuite, si votre application .Net est **exécutée** par **IIS**, vous pouvez la **redémarrer** avec :
```
iisreset /noforce
```
Ensuite, pour commencer le débogage, vous devez fermer tous les fichiers ouverts et dans l'onglet **Débogage**, sélectionnez **Attacher au processus...** :

![](<../../.gitbook/assets/image (280).png>)

Ensuite, sélectionnez **w3wp.exe** pour vous connecter au serveur **IIS** et cliquez sur **attacher** :

![](<../../.gitbook/assets/image (281).png>)

Maintenant que nous déboguons le processus, il est temps de l'arrêter et de charger tous les modules. Cliquez d'abord sur _Débogage >> Interrompre tout_ puis cliquez sur _**Débogage >> Fenêtres >> Modules**_ :

![](<../../.gitbook/assets/image (286).png>)

![](<../../.gitbook/assets/image (283).png>)

Cliquez sur n'importe quel module dans **Modules** et sélectionnez **Ouvrir tous les modules** :

![](<../../.gitbook/assets/image (284).png>)

Cliquez avec le bouton droit de la souris sur n'importe quel module dans **Explorateur d'assemblage** et cliquez sur **Trier les assemblages** :

![](<../../.gitbook/assets/image (285).png>)

## Décompilateur Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Débogage des DLL

### Utilisation de IDA

* **Charger rundll32** (64 bits dans C:\Windows\System32\rundll32.exe et 32 bits dans C:\Windows\SysWOW64\rundll32.exe)
* Sélectionnez le débogueur **Windbg**
* Sélectionnez "**Suspendre lors du chargement/déchargement de la bibliothèque**"

![](<../../.gitbook/assets/image (135).png>)

* Configurez les **paramètres** de l'exécution en indiquant le **chemin de la DLL** et la fonction que vous souhaitez appeler :

![](<../../.gitbook/assets/image (136).png>)

Ensuite, lorsque vous commencez le débogage, **l'exécution s'arrêtera lorsque chaque DLL est chargée**, puis, lorsque rundll32 charge votre DLL, l'exécution s'arrêtera.

Mais comment accéder au code de la DLL qui a été chargée ? Avec cette méthode, je ne sais pas comment.

### Utilisation de x64dbg/x32dbg

* **Charger rundll32** (64 bits dans C:\Windows\System32\rundll32.exe et 32 bits dans C:\Windows\SysWOW64\rundll32.exe)
* **Modifier la ligne de commande** ( _Fichier --> Modifier la ligne de commande_ ) et définissez le chemin de la DLL et la fonction que vous souhaitez appeler, par exemple : "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii\_2.dll",DLLMain
* Modifiez _Options --> Paramètres_ et sélectionnez "**Entrée DLL**".
* Ensuite, **démarrez l'exécution**, le débogueur s'arrêtera à chaque point d'entrée de la DLL, à un moment donné, vous vous arrêterez dans l'entrée de la DLL de votre DLL. À partir de là, recherchez simplement les points où vous souhaitez mettre un point d'arrêt.

Notez que lorsque l'exécution est arrêtée pour une raison quelconque dans win64dbg, vous pouvez voir **dans quel code vous êtes** en regardant en haut de la fenêtre win64dbg :

![](<../../.gitbook/assets/image (137).png>)

Ensuite, en regardant cela, vous pouvez voir quand l'exécution a été arrêtée dans la DLL que vous souhaitez déboguer.

## Applications GUI / Jeux vidéo

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) est un programme utile pour trouver où les valeurs importantes sont enregistrées dans la mémoire d'un jeu en cours d'exécution et les modifier. Plus d'informations dans :

{% content-ref url="cheat-engine.md" %}
[cheat-engine.md](cheat-engine.md)
{% endcontent-ref %}

## ARM & MIPS

{% embed url="https://github.com/nongiach/arm_now" %}

## Shellcodes

### Débogage d'un shellcode avec blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) allouera le **shellcode** dans un espace de mémoire, vous indiquera l'adresse mémoire où le shellcode a été alloué et arrêtera l'exécution.\
Ensuite, vous devez **attacher un débogueur** (Ida ou x64dbg) au processus et mettre un **point d'arrêt à l'adresse mémoire indiquée** et **reprendre** l'exécution. De cette façon, vous déboguez le shellcode.

La page des versions publiées sur GitHub contient des fichiers zip contenant les versions compilées : [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Vous pouvez trouver une version légèrement modifiée de Blobrunner dans le lien suivant. Pour la compiler, il vous suffit de **créer un projet C/C++ dans Visual Studio Code, copier et coller le code et le compiler**.

{% content-ref url="blobrunner.md" %}
[blobrunner.md](blobrunner.md)
{% endcontent-ref %}

### Débogage d'un shellcode avec jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)est très similaire à blobrunner. Il allouera le **shellcode** dans un espace de mémoire et démarrera une **boucle éternelle**. Vous devez ensuite **attacher le débogueur** au processus, **lancer le démarrage, attendre 2 à 5 secondes et appuyer sur stop**, et vous vous retrouverez dans la **boucle éternelle**. Passez à l'instruction suivante de la boucle éternelle car il s'agira d'un appel au shellcode, et enfin vous vous retrouverez à exécuter le shellcode.

![](<../../.gitbook/assets/image (397).png>)

Vous pouvez télécharger une version compilée de [jmp2it sur la page des versions](https://github.com/adamkramer/jmp2it/releases/).

### Débogage du shellcode à l'aide de Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) est l'interface graphique de radare. Avec Cutter, vous pouvez émuler le shellcode et l'inspecter dynamiquement.

Notez que Cutter vous permet d'"Ouvrir un fichier" et "Ouvrir un shellcode". Dans mon cas, lorsque j'ai ouvert le shellcode en tant que fichier, il l'a décompilé correctement, mais lorsque je l'ai ouvert en tant que shellcode, il ne l'a pas fait :

![](<../../.gitbook/assets/image (400).png>)

Pour démarrer l'émulation à l'endroit souhaité, définissez un point d'arrêt là-bas et apparemment Cutter démarrera automatiquement l'émulation à partir de là :

![](<../../.gitbook/assets/image (399).png>)

![](<../../.gitbook/assets/image (401).png>)

Vous pouvez voir la pile par exemple dans un affichage hexadécimal :

![](<../../.gitbook/assets/image (402).png>)
### Désobfuscation du shellcode et obtention des fonctions exécutées

Vous devriez essayer [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7\&pid=152).\
Il vous indiquera quelles fonctions le shellcode utilise et si le shellcode se **décode** lui-même en mémoire.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg compte également sur un lanceur graphique où vous pouvez sélectionner les options souhaitées et exécuter le shellcode.

![](<../../.gitbook/assets/image (398).png>)

L'option **Create Dump** permettra de créer un dump du shellcode final si des modifications sont apportées au shellcode de manière dynamique en mémoire (utile pour télécharger le shellcode décodé). L'**offset de démarrage** peut être utile pour démarrer le shellcode à un offset spécifique. L'option **Debug Shell** est utile pour déboguer le shellcode en utilisant le terminal scDbg (cependant, je trouve que l'une des options expliquées précédemment est meilleure pour cette question car vous pourrez utiliser Ida ou x64dbg).

### Désassemblage à l'aide de CyberChef

Téléchargez votre fichier shellcode en tant qu'entrée et utilisez la recette suivante pour le décompiler: [https://gchq.github.io/CyberChef/#recipe=To\_Hex('Space',0)Disassemble\_x86('32','Full%20x86%20architecture',16,0,true,true)](https://gchq.github.io/CyberChef/#recipe=To\_Hex\('Space',0\)Disassemble\_x86\('32','Full%20x86%20architecture',16,0,true,true\))

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Cet obfuscateur **modifie toutes les instructions pour `mov`** (oui, vraiment cool). Il utilise également des interruptions pour changer les flux d'exécution. Pour plus d'informations sur son fonctionnement:

* [https://www.youtube.com/watch?v=2VF\_wPkiBJY](https://www.youtube.com/watch?v=2VF\_wPkiBJY)
* [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf)

Si vous avez de la chance, [demovfuscator](https://github.com/kirschju/demovfuscator) déobfusquera le binaire. Il a plusieurs dépendances.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Et [installez keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Si vous jouez à un **CTF, cette solution de contournement pour trouver le drapeau** pourrait être très utile: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trouvez les vulnérabilités les plus importantes afin de pouvoir les corriger plus rapidement. Intruder suit votre surface d'attaque, effectue des analyses de menace proactives, trouve des problèmes dans l'ensemble de votre pile technologique, des API aux applications web et aux systèmes cloud. [**Essayez-le gratuitement**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) dès aujourd'hui.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Rust

Pour trouver le **point d'entrée**, recherchez les fonctions par `::main` comme dans:

![](<../../.gitbook/assets/image (612).png>)

Dans ce cas, le binaire s'appelait authenticator, il est donc assez évident que c'est la fonction principale intéressante.\
Avoir le **nom** des **fonctions** appelées, recherchez-les sur **Internet** pour en apprendre davantage sur leurs **entrées** et **sorties**.

## **Delphi**

Pour les binaires compilés en Delphi, vous pouvez utiliser [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Si vous devez inverser un binaire Delphi, je vous suggère d'utiliser le plugin IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Appuyez simplement sur **ATL+f7** (importez le plugin python dans IDA) et sélectionnez le plugin python.

Ce plugin exécutera le binaire et résoudra dynamiquement les noms de fonction au début du débogage. Après avoir démarré le débogage, appuyez à nouveau sur le bouton Démarrer (le bouton vert ou f9) et un point d'arrêt sera atteint au début du code réel.

C'est également très intéressant car si vous appuyez sur un bouton dans l'application graphique, le débogueur s'arrêtera dans la fonction exécutée par ce bouton.

## Golang

Si vous devez inverser un binaire Golang, je vous suggère d'utiliser le plugin IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Appuyez simplement sur **ATL+f7** (importez le plugin python dans IDA) et sélectionnez le plugin python.

Cela résoudra les noms des fonctions.

## Python compilé

Sur cette page, vous pouvez trouver comment obtenir le code python à partir d'un binaire compilé ELF/EXE python:

{% content-ref url="../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md" %}
[.pyc.md](../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md)
{% endcontent-ref %}

## GBA - Game Body Advance

Si vous obtenez le **binaire** d'un jeu GBA, vous pouvez utiliser différents outils pour **émuler** et **déboguer**:

* [**no$gba**](https://problemkaputt.de/gba.htm) (_Téléchargez la version de débogage_) - Contient un débogueur avec interface
* [**mgba** ](https://mgba.io)- Contient un débogueur CLI
* [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin Ghidra
* [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin Ghidra

Dans [**no$gba**](https://problemkaputt.de/gba.htm), dans _**Options --> Emulation Setup --> Controls**_\*\* \*\* vous pouvez voir comment appuyer sur les **boutons** de la Game Boy Advance

![](<../../.gitbook/assets/image (578).png>)

Lorsqu'il est enfoncé, chaque **touche a une valeur** pour l'identifier:
```
A = 1
B = 2
SELECT = 4
START = 8
RIGHT = 16
LEFT = 32
UP = 64
DOWN = 128
R = 256
L = 256
```
Donc, dans ce genre de programmes, une partie intéressante sera **comment le programme traite l'entrée de l'utilisateur**. À l'adresse **0x4000130**, vous trouverez la fonction couramment utilisée : **KEYINPUT**.

![](<../../.gitbook/assets/image (579).png>)

Dans l'image précédente, vous pouvez voir que la fonction est appelée depuis **FUN\_080015a8** (adresses : _0x080015fa_ et _0x080017ac_).

Dans cette fonction, après quelques opérations d'initialisation (sans importance) :
```c
void FUN_080015a8(void)

{
ushort uVar1;
undefined4 uVar2;
undefined4 uVar3;
ushort uVar4;
int iVar5;
ushort *puVar6;
undefined *local_2c;

DISPCNT = 0x1140;
FUN_08000a74();
FUN_08000ce4(1);
DISPCNT = 0x404;
FUN_08000dd0(&DAT_02009584,0x6000000,&DAT_030000dc);
FUN_08000354(&DAT_030000dc,0x3c);
uVar4 = DAT_030004d8;
```
On a trouvé ce code :
```c
do {
DAT_030004da = uVar4; //This is the last key pressed
DAT_030004d8 = KEYINPUT | 0xfc00;
puVar6 = &DAT_0200b03c;
uVar4 = DAT_030004d8;
do {
uVar2 = DAT_030004dc;
uVar1 = *puVar6;
if ((uVar1 & DAT_030004da & ~uVar4) != 0) {
```
Le dernier "if" vérifie si **`uVar4`** se trouve dans les **dernières clés** et n'est pas la clé actuelle, également appelée relâchement d'un bouton (la clé actuelle est stockée dans **`uVar1`**).
```c
if (uVar1 == 4) {
DAT_030000d4 = 0;
uVar3 = FUN_08001c24(DAT_030004dc);
FUN_08001868(uVar2,0,uVar3);
DAT_05000000 = 0x1483;
FUN_08001844(&DAT_0200ba18);
FUN_08001844(&DAT_0200ba20,&DAT_0200ba40);
DAT_030000d8 = 0;
uVar4 = DAT_030004d8;
}
else {
if (uVar1 == 8) {
if (DAT_030000d8 == 0xf3) {
DISPCNT = 0x404;
FUN_08000dd0(&DAT_02008aac,0x6000000,&DAT_030000dc);
FUN_08000354(&DAT_030000dc,0x3c);
uVar4 = DAT_030004d8;
}
}
else {
if (DAT_030000d4 < 8) {
DAT_030000d4 = DAT_030000d4 + 1;
FUN_08000864();
if (uVar1 == 0x10) {
DAT_030000d8 = DAT_030000d8 + 0x3a;
```
Dans le code précédent, vous pouvez voir que nous comparons **uVar1** (l'endroit où se trouve **la valeur du bouton pressé**) avec certaines valeurs :

* Tout d'abord, il est comparé avec la **valeur 4** (bouton **SELECT**) : Dans le défi, ce bouton efface l'écran.
* Ensuite, il est comparé avec la **valeur 8** (bouton **START**) : Dans le défi, cela vérifie si le code est valide pour obtenir le drapeau.
* Dans ce cas, la variable **`DAT_030000d8`** est comparée avec 0xf3 et si la valeur est la même, du code est exécuté.
* Dans tous les autres cas, un cont (`DAT_030000d4`) est vérifié. C'est un cont car il ajoute 1 juste après avoir entré dans le code.\
Si moins de 8, quelque chose qui implique **l'ajout** de valeurs à \*\*`DAT_030000d8` \*\* est fait (essentiellement, il ajoute les valeurs des touches pressées dans cette variable tant que le cont est inférieur à 8).

Ainsi, dans ce défi, en connaissant les valeurs des boutons, vous deviez **appuyer sur une combinaison d'une longueur inférieure à 8 pour que l'addition résultante soit 0xf3**.

**Référence pour ce tutoriel :** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy

{% embed url="https://www.youtube.com/watch?v=VVbRe7wr3G4" %}

## Cours

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Déobfuscation binaire)


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trouvez les vulnérabilités les plus importantes afin de pouvoir les corriger plus rapidement. Intruder suit votre surface d'attaque, effectue des analyses de menace proactives, trouve des problèmes dans l'ensemble de votre pile technologique, des API aux applications web et aux systèmes cloud. [**Essayez-le gratuitement**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) dès aujourd'hui.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Vous travaillez dans une **entreprise de cybersécurité** ? Vous souhaitez voir votre **entreprise annoncée dans HackTricks** ? ou souhaitez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
