<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


# Décompilateur Wasm / Compilateur Wat

En ligne :

* Utilisez [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) pour **décompiler** du wasm \(binaire\) en wat \(texte clair\)
* Utilisez [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) pour **compiler** du wat en wasm
* Vous pouvez également essayer d'utiliser [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) pour décompiler

Logiciel :

* [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
* [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

# Décompilateur .Net

[https://github.com/icsharpcode/ILSpy](https://github.com/icsharpcode/ILSpy)  
[Plugin ILSpy pour Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode) : Vous pouvez l'avoir dans n'importe quel système d'exploitation \(vous pouvez l'installer directement depuis VSCode, pas besoin de télécharger le git. Cliquez sur **Extensions** et **recherchez ILSpy**\).  
Si vous avez besoin de **décompiler**, **modifier** et **recompiler** à nouveau, vous pouvez utiliser : [**https://github.com/0xd4d/dnSpy/releases**](https://github.com/0xd4d/dnSpy/releases) \(**Clic droit -&gt; Modifier la méthode** pour changer quelque chose à l'intérieur d'une fonction\).  
Vous pouvez également essayer [https://www.jetbrains.com/es-es/decompiler/](https://www.jetbrains.com/es-es/decompiler/)

## Journalisation DNSpy

Pour faire en sorte que **DNSpy enregistre certaines informations dans un fichier**, vous pouvez utiliser ces lignes de code .Net :
```bash
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
## Débogage avec DNSpy

Pour déboguer du code en utilisant DNSpy, vous devez :

Tout d'abord, changer les **attributs d'Assembly** liés au **débogage** :

![](../../.gitbook/assets/image%20%287%29.png)

De :
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
Je suis prêt à vous aider. Que puis-je traduire pour vous ?
```text
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
Et cliquez sur **compiler** :

![](../../.gitbook/assets/image%20%28314%29%20%281%29.png)

Ensuite, enregistrez le nouveau fichier sur _**Fichier &gt;&gt; Enregistrer le module...**_ :

![](../../.gitbook/assets/image%20%28261%29.png)

Ceci est nécessaire car si vous ne le faites pas, à **l'exécution** plusieurs **optimisations** seront appliquées au code et il pourrait être possible qu'en déboguant un **point d'arrêt ne soit jamais atteint** ou que certaines **variables n'existent pas**.

Ensuite, si votre application .Net est **exécutée** par **IIS**, vous pouvez la **redémarrer** avec :
```text
iisreset /noforce
```
Ensuite, pour commencer le débogage, vous devez fermer tous les fichiers ouverts et dans l'onglet **Débogage**, sélectionnez **Attacher au processus...** :

![](../../.gitbook/assets/image%20%28166%29.png)

Ensuite, sélectionnez **w3wp.exe** pour vous connecter au **serveur IIS** et cliquez sur **Joindre** :

![](../../.gitbook/assets/image%20%28274%29.png)

Maintenant que nous déboguons le processus, il est temps de l'arrêter et de charger tous les modules. Tout d'abord, cliquez sur _Débogage &gt;&gt; Interrompre tout_ puis cliquez sur _**Débogage &gt;&gt; Fenêtres &gt;&gt; Modules**_ :

![](../../.gitbook/assets/image%20%28210%29.png)

![](../../.gitbook/assets/image%20%28341%29.png)

Cliquez sur n'importe quel module dans **Modules** et sélectionnez **Ouvrir tous les modules** :

![](../../.gitbook/assets/image%20%28216%29.png)

Cliquez avec le bouton droit sur n'importe quel module dans **Explorateur d'assemblage** et cliquez sur **Trier les assemblages** :

![](../../.gitbook/assets/image%20%28130%29.png)

# Décompilateur Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)  
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

# Débogage des DLL

## Utilisation d'IDA

* **Chargez rundll32** \(64 bits dans C:\Windows\System32\rundll32.exe et 32 bits dans C:\Windows\SysWOW64\rundll32.exe\)
* Sélectionnez le débogueur **Windbg**
* Sélectionnez "**Suspendre lors du chargement/déchargement de la bibliothèque**"

![](../../.gitbook/assets/image%20%2869%29.png)

* Configurez les **paramètres** de l'exécution en mettant le **chemin d'accès à la DLL** et la fonction que vous voulez appeler :

![](../../.gitbook/assets/image%20%28325%29.png)

Ensuite, lorsque vous commencez le débogage, **l'exécution s'arrêtera lorsque chaque DLL sera chargée**, puis, lorsque rundll32 chargera votre DLL, l'exécution s'arrêtera.

Mais comment pouvez-vous accéder au code de la DLL qui a été chargée ? En utilisant cette méthode, je ne sais pas comment.

## Utilisation de x64dbg/x32dbg

* **Chargez rundll32** \(64 bits dans C:\Windows\System32\rundll32.exe et 32 bits dans C:\Windows\SysWOW64\rundll32.exe\)
* **Modifiez la ligne de commande** \( _Fichier --&gt; Modifier la ligne de commande_ \) et définissez le chemin de la DLL et la fonction que vous voulez appeler, par exemple : "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\14.ridii\_2.dll",DLLMain
* Changez _Options --&gt; Paramètres_ et sélectionnez "**Entrée DLL**".
* Ensuite, **démarrez l'exécution**, le débogueur s'arrêtera à chaque dll principale, à un moment donné, vous vous arrêterez dans l'entrée de la DLL de votre DLL. À partir de là, recherchez simplement les points où vous voulez mettre un point d'arrêt.

Notez que lorsque l'exécution est arrêtée pour une raison quelconque dans win64dbg, vous pouvez voir **dans quel code vous êtes** en regardant en haut de la fenêtre win64dbg :

![](../../.gitbook/assets/image%20%28181%29.png)

Ensuite, en regardant cela, vous pouvez voir quand l'exécution a été arrêtée dans la DLL que vous voulez déboguer.

# ARM & MIPS

{% embed url="https://github.com/nongiach/arm\_now" %}

# Shellcodes

## Débogage d'un shellcode avec blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) va **allouer** le **shellcode** dans un espace de mémoire, vous **indiquer** l'**adresse mémoire** où le shellcode a été alloué et **arrêter** l'exécution.  
Ensuite, vous devez **attacher un débogueur** \(Ida ou x64dbg\) au processus et mettre un **point d'arrêt à l'adresse mémoire indiquée** et **reprendre** l'exécution. De cette façon, vous déboguez le shellcode.

La page des versions publiées contient des fichiers zip contenant les versions compilées : [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)  
Vous pouvez trouver une version légèrement modifiée de Blobrunner dans le lien suivant. Pour la compiler, il suffit de **créer un projet C/C++ dans Visual Studio Code, de copier et coller le code et de le compiler**.

{% page-ref page="blobrunner.md" %}

## Débogage d'un shellcode avec jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)est très similaire à blobrunner. Il va **allouer** le **shellcode** dans un espace de mémoire et démarrer une **boucle éternelle**. Vous devez ensuite **attacher le débogueur** au processus, **démarrer, attendre 2 à 5 secondes et appuyer sur stop** et vous vous retrouverez dans la **boucle éternelle**. Sautez à l'instruction suivante de la boucle éternelle car ce sera un appel au shellcode, et enfin vous vous retrouverez à exécuter le shellcode.

![](../../.gitbook/assets/image%20%28403%29.png)

Vous pouvez télécharger une version compilée de [jmp2it dans la page des versions](https://github.com/adamkramer/jmp2it/releases/).

## Débogage de shellcode à l'aide de Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) est l'interface graphique de radare. Avec Cutter, vous pouvez émuler le shellcode et l'inspecter dynamiquement.

Notez que Cutter vous permet d'ouvrir un fichier et un shellcode. Dans mon cas, lorsque j'ai ouvert le shellcode en tant que fichier, il l'a décompilé correctement, mais lorsque je l'ai ouvert en tant que shellcode, il ne l'a pas fait :

![](../../.gitbook/assets/image%20%28254%29.png)

Pour démarrer l'émulation à l'endroit où vous le souhaitez, définissez un point d'arrêt là-bas et apparemment Cutter démarrera automatiquement l'émulation à partir de là :

![](../../.gitbook/assets/image%20%28402%29.png)

![](../../.gitbook/assets/image%20%28343%29.png)

Vous pouvez voir la pile, par exemple, dans un dump hexadécimal :

![](../../.gitbook/assets/image%20%28404%29.png)

## Désobfuscation de shellcode et obtention des fonctions exécutées

Vous devriez essayer [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).  
Il vous indiquera les fonctions que le shellcode utilise et si le shellcode se décode lui-même en mémoire.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg dispose également d'un lanceur graphique où vous pouvez sélectionner les options que vous souhaitez et exécuter le shellcode.

![](../../.gitbook/assets/image%20%28401%29.png)

L'option **Create Dump** permettra de déverser le shellcode final si des modifications sont apportées au shellcode dynamiquement en mémoire \(utile pour télécharger le shellcode décodé\). L'**offset de départ** peut être utile pour démarrer le shellcode à un offset spécifique. L'option **Debug Shell** est utile pour déboguer le shellcode en utilisant le terminal scDbg \(cependant, je trouve que toutes les options expliquées précédemment sont meilleures pour cette question car vous pourrez utiliser Ida ou x64dbg\).

## Désassemblage à l'aide de CyberChef

Téléchargez votre fichier shellcode en tant qu'entrée et utilisez la recette suivante pour le décompiler: [https://gchq.github.io/CyberChef/\#recipe=To\_Hex\('Space',0\)Disassemble\_x86\('32','Full%20x86%20architecture',16,0,true,true\)](https://gchq.github.io/CyberChef/#recipe=To_Hex%28'Space',0%29Disassemble_x86%28'32','Full%20x86%20architecture',16,0,true,true%29)

# [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Cet obscurcisseur change toutes les instructions pour `mov`\(oui, vraiment cool\). Il utilise également des interruptions pour changer les flux d'exécution. Pour plus d'informations sur son fonctionnement:

* [https://www.youtube.com/watch?v=2VF\_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
* [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Si vous avez de la chance, [demovfuscator](https://github.com/kirschju/demovfuscator) déofusquera le binaire. Il a plusieurs dépendances.
```text
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Et [installez keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) \(`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`\)

Si vous jouez à un **CTF, cette solution de contournement pour trouver le flag** pourrait être très utile: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html) 

# Delphi

Pour les binaires compilés en Delphi, vous pouvez utiliser [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

# Cours

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) \(Déobfuscation binaire\)



<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une **entreprise de cybersécurité**? Voulez-vous voir votre **entreprise annoncée dans HackTricks**? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF**? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
