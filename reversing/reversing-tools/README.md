{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}

# Guide de décompilation Wasm et de compilation Wat

Dans le domaine de **WebAssembly**, les outils pour **décompiler** et **compiler** sont essentiels pour les développeurs. Ce guide présente quelques ressources en ligne et logiciels pour gérer les fichiers **Wasm (WebAssembly binaire)** et **Wat (WebAssembly texte)**.

## Outils en ligne

- Pour **décompiler** Wasm en Wat, l'outil disponible sur [la démo wasm2wat de Wabt](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) est très utile.
- Pour **compiler** Wat en Wasm, [la démo wat2wasm de Wabt](https://webassembly.github.io/wabt/demo/wat2wasm/) sert à cet effet.
- Une autre option de décompilation peut être trouvée sur [web-wasmdec](https://wwwg.github.io/web-wasmdec/).

## Solutions logicielles

- Pour une solution plus robuste, [JEB de PNF Software](https://www.pnfsoftware.com/jeb/demo) offre des fonctionnalités étendues.
- Le projet open-source [wasmdec](https://github.com/wwwg/wasmdec) est également disponible pour les tâches de décompilation.

# Ressources de décompilation .Net

La décompilation des assemblies .Net peut être réalisée avec des outils tels que :

- [ILSpy](https://github.com/icsharpcode/ILSpy), qui propose également un [plugin pour Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode), permettant une utilisation multiplateforme.
- Pour des tâches impliquant **décompilation**, **modification** et **recompilation**, [dnSpy](https://github.com/0xd4d/dnSpy/releases) est fortement recommandé. **Un clic droit** sur une méthode et le choix de **Modifier la méthode** permettent des modifications de code.
- [dotPeek de JetBrains](https://www.jetbrains.com/es-es/decompiler/) est une autre alternative pour décompiler des assemblies .Net.

## Amélioration du débogage et de la journalisation avec DNSpy

### Journalisation DNSpy
Pour enregistrer des informations dans un fichier en utilisant DNSpy, incorporez le snippet de code .Net suivant :

%%%cpp
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Mot de passe : " + password + "\n");
%%%

### Débogage DNSpy
Pour un débogage efficace avec DNSpy, une séquence d'étapes est recommandée pour ajuster les **attributs d'assembly** pour le débogage, en s'assurant que les optimisations qui pourraient entraver le débogage sont désactivées. Ce processus inclut le changement des paramètres `DebuggableAttribute`, la recompilation de l'assembly et l'enregistrement des modifications.

De plus, pour déboguer une application .Net exécutée par **IIS**, exécuter `iisreset /noforce` redémarre IIS. Pour attacher DNSpy au processus IIS pour le débogage, le guide indique de sélectionner le processus **w3wp.exe** dans DNSpy et de commencer la session de débogage.

Pour une vue complète des modules chargés pendant le débogage, il est conseillé d'accéder à la fenêtre **Modules** dans DNSpy, suivie de l'ouverture de tous les modules et du tri des assemblies pour une navigation et un débogage plus faciles.

Ce guide encapsule l'essence de la décompilation WebAssembly et .Net, offrant un chemin pour les développeurs afin de naviguer ces tâches avec aisance.

## **Décompilateur Java**
Pour décompiler le bytecode Java, ces outils peuvent être très utiles :
- [jadx](https://github.com/skylot/jadx)
- [JD-GUI](https://github.com/java-decompiler/jd-gui/releases)

## **Débogage des DLL**
### Utilisation d'IDA
- **Rundll32** est chargé à partir de chemins spécifiques pour les versions 64 bits et 32 bits.
- **Windbg** est sélectionné comme débogueur avec l'option de suspension lors du chargement/déchargement de la bibliothèque activée.
- Les paramètres d'exécution incluent le chemin de la DLL et le nom de la fonction. Cette configuration interrompt l'exécution lors du chargement de chaque DLL.

### Utilisation de x64dbg/x32dbg
- Semblable à IDA, **rundll32** est chargé avec des modifications de ligne de commande pour spécifier la DLL et la fonction.
- Les paramètres sont ajustés pour se briser à l'entrée de la DLL, permettant de définir un point d'arrêt au point d'entrée de la DLL souhaité.

### Images
- Les points d'arrêt d'exécution et les configurations sont illustrés par des captures d'écran.

## **ARM & MIPS**
- Pour l'émulation, [arm_now](https://github.com/nongiach/arm_now) est une ressource utile.

## **Shellcodes**
### Techniques de débogage
- **Blobrunner** et **jmp2it** sont des outils pour allouer des shellcodes en mémoire et les déboguer avec Ida ou x64dbg.
- Blobrunner [versions](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)
- jmp2it [version compilée](https://github.com/adamkramer/jmp2it/releases/)
- **Cutter** offre une émulation et une inspection de shellcode basées sur une interface graphique, mettant en évidence les différences dans le traitement des shellcodes en tant que fichier par rapport à un shellcode direct.

### Déobfuscation et analyse
- **scdbg** fournit des informations sur les fonctions de shellcode et les capacités de déobfuscation.
%%%bash
scdbg.exe -f shellcode # Informations de base
scdbg.exe -f shellcode -r # Rapport d'analyse
scdbg.exe -f shellcode -i -r # Hooks interactifs
scdbg.exe -f shellcode -d # Dump du shellcode décodé
scdbg.exe -f shellcode /findsc # Trouver le décalage de départ
scdbg.exe -f shellcode /foff 0x0000004D # Exécuter à partir du décalage
%%%

- **CyberChef** pour désassembler le shellcode : [recette CyberChef](https://gchq.github.io/CyberChef/#recipe=To_Hex%28'Space',0%29Disassemble_x86%28'32','Full%20x86%20architecture',16,0,true,true%29)

## **Movfuscator**
- Un obfuscateur qui remplace toutes les instructions par `mov`.
- Les ressources utiles incluent une [explication YouTube](https://www.youtube.com/watch?v=2VF_wPkiBJY) et [des diapositives PDF](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf).
- **demovfuscator** pourrait inverser l'obfuscation de movfuscator, nécessitant des dépendances comme `libcapstone-dev` et `libz3-dev`, et l'installation de [keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md).

## **Delphi**
- Pour les binaires Delphi, [IDR](https://github.com/crypto2011/IDR) est recommandé.


# Cours

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) \(Déobfuscation binaire\)



{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
