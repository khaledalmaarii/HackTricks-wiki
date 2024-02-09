<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert de l'équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

# Guide de décompilation Wasm et compilation Wat

Dans le domaine de **WebAssembly**, les outils de **décompilation** et de **compilation** sont essentiels pour les développeurs. Ce guide présente quelques ressources en ligne et logiciels pour manipuler les fichiers **Wasm (binaire WebAssembly)** et **Wat (texte WebAssembly)**.

## Outils en ligne

- Pour **décompiler** Wasm en Wat, l'outil disponible sur [la démo wasm2wat de Wabt](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) est pratique.
- Pour **compiler** Wat en Wasm, [la démo wat2wasm de Wabt](https://webassembly.github.io/wabt/demo/wat2wasm/) remplit sa fonction.
- Une autre option de décompilation est disponible sur [web-wasmdec](https://wwwg.github.io/web-wasmdec/).

## Solutions logicielles

- Pour une solution plus robuste, [JEB par PNF Software](https://www.pnfsoftware.com/jeb/demo) offre des fonctionnalités étendues.
- Le projet open-source [wasmdec](https://github.com/wwwg/wasmdec) est également disponible pour les tâches de décompilation.

# Ressources de décompilation .Net

La décompilation des assemblies .Net peut être réalisée avec des outils tels que :

- [ILSpy](https://github.com/icsharpcode/ILSpy), qui propose également un [plugin pour Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode), permettant une utilisation multiplateforme.
- Pour les tâches de **décompilation**, **modification** et **recompilation**, [dnSpy](https://github.com/0xd4d/dnSpy/releases) est vivement recommandé. En cliquant avec le bouton droit sur une méthode et en choisissant **Modifier la méthode**, vous pouvez apporter des modifications au code.
- [dotPeek de JetBrains](https://www.jetbrains.com/es-es/decompiler/) est une autre alternative pour la décompilation des assemblies .Net.

## Amélioration du débogage et du journalisation avec DNSpy

### Journalisation DNSpy
Pour journaliser des informations dans un fichier à l'aide de DNSpy, incorporez le snippet de code .Net suivant :

%%%cpp
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Mot de passe : " + password + "\n");
%%%

### Débogage DNSpy
Pour un débogage efficace avec DNSpy, une séquence d'étapes est recommandée pour ajuster les **attributs de l'Assembly** pour le débogage, en veillant à ce que les optimisations qui pourraient entraver le débogage soient désactivées. Ce processus inclut la modification des paramètres de `DebuggableAttribute`, la recompilation de l'assembly et l'enregistrement des modifications.

De plus, pour déboguer une application .Net exécutée par **IIS**, l'exécution de `iisreset /noforce` redémarre IIS. Pour attacher DNSpy au processus IIS pour le débogage, le guide explique comment sélectionner le processus **w3wp.exe** dans DNSpy et démarrer la session de débogage.

Pour une vue complète des modules chargés lors du débogage, il est conseillé d'accéder à la fenêtre **Modules** dans DNSpy, puis d'ouvrir tous les modules et de trier les assemblies pour une navigation et un débogage plus faciles.

Ce guide encapsule l'essence de la décompilation de WebAssembly et .Net, offrant un chemin aux développeurs pour naviguer facilement dans ces tâches.

## **Décompilateur Java**
Pour décompiler le bytecode Java, ces outils peuvent être très utiles :
- [jadx](https://github.com/skylot/jadx)
- [JD-GUI](https://github.com/java-decompiler/jd-gui/releases)

## **Débogage des DLL**
### Utilisation d'IDA
- **Rundll32** est chargé à partir de chemins spécifiques pour les versions 64 bits et 32 bits.
- **Windbg** est sélectionné comme débogueur avec l'option de suspension lors du chargement/déchargement de la bibliothèque activée.
- Les paramètres d'exécution incluent le chemin de la DLL et le nom de la fonction. Cette configuration arrête l'exécution à chaque chargement de DLL.

### Utilisation de x64dbg/x32dbg
- Similaire à IDA, **rundll32** est chargé avec des modifications en ligne de commande pour spécifier la DLL et la fonction.
- Les paramètres sont ajustés pour interrompre à l'entrée de la DLL, permettant de définir un point d'arrêt au point d'entrée de la DLL souhaité.

### Images
- Les points d'arrêt d'exécution et les configurations sont illustrés à travers des captures d'écran.

## **ARM & MIPS**
- Pour l'émulation, [arm_now](https://github.com/nongiach/arm_now) est une ressource utile.

## **Shellcodes**
### Techniques de débogage
- **Blobrunner** et **jmp2it** sont des outils pour allouer des shellcodes en mémoire et les déboguer avec Ida ou x64dbg.
- Blobrunner [versions](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)
- jmp2it [version compilée](https://github.com/adamkramer/jmp2it/releases/)
- **Cutter** offre une émulation de shellcode basée sur une interface graphique et une inspection, mettant en évidence les différences dans le traitement des shellcodes en tant que fichier par rapport au shellcode direct.

### Déobfuscation et Analyse
- **scdbg** fournit des informations sur les fonctions des shellcodes et des capacités de déobfuscation.
%%%bash
scdbg.exe -f shellcode # Informations de base
scdbg.exe -f shellcode -r # Rapport d'analyse
scdbg.exe -f shellcode -i -r # Hooks interactifs
scdbg.exe -f shellcode -d # Extraction du shellcode décodé
scdbg.exe -f shellcode /findsc # Rechercher le décalage de départ
scdbg.exe -f shellcode /foff 0x0000004D # Exécuter à partir du décalage
%%%

- **CyberChef** pour désassembler les shellcodes : [Recette CyberChef](https://gchq.github.io/CyberChef/#recipe=To_Hex%28'Space',0%29Disassemble_x86%28'32','Full%20x86%20architecture',16,0,true,true%29)

## **Movfuscator**
- Un obfuscateur qui remplace toutes les instructions par `mov`.
- Des ressources utiles incluent une [explication YouTube](https://www.youtube.com/watch?v=2VF_wPkiBJY) et des [diapositives PDF](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf).
- **demovfuscator** pourrait inverser l'obfuscation du movfuscator, nécessitant des dépendances comme `libcapstone-dev` et `libz3-dev`, et l'installation de [keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md).

## **Delphi**
- Pour les binaires Delphi, [IDR](https://github.com/crypto2011/IDR) est recommandé.


# Cours

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) \(Déobfuscation binaire\)



<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert de l'équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
