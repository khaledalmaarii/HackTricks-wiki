# Kerberos Double Hop Problem

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Introduction

Tatizo la "Double Hop" la Kerberos linaonekana wakati mshambuliaji anajaribu kutumia **uthibitishaji wa Kerberos kati ya hops mbili**, kwa mfano kutumia **PowerShell**/**WinRM**.

Wakati **uthibitishaji** unapotokea kupitia **Kerberos**, **akili** **hazihifadhiwi** katika **kumbukumbu.** Hivyo, ikiwa unakimbia mimikatz hu **wezi kupata akili** za mtumiaji kwenye mashine hata kama anafanya kazi.

Hii ni kwa sababu wakati wa kuungana na Kerberos hatua hizi zinafuatwa:

1. User1 anatoa akili na **meneja wa eneo** anarudisha **TGT** ya Kerberos kwa User1.
2. User1 anatumia **TGT** kuomba **tiketi ya huduma** ili **kuungana** na Server1.
3. User1 **anaungana** na **Server1** na anatoa **tiketi ya huduma**.
4. **Server1** **hainayo** **akili** za User1 zilizohifadhiwa au **TGT** ya User1. Hivyo, wakati User1 kutoka Server1 anajaribu kuingia kwenye seva ya pili, hawezi **kujiandikisha**.

### Unconstrained Delegation

Ikiwa **unconstrained delegation** imewezeshwa kwenye PC, hii haitatokea kwani **Server** itapata **TGT** ya kila mtumiaji anayefikia. Zaidi ya hayo, ikiwa unconstrained delegation inatumika unaweza **kudhoofisha Meneja wa Eneo** kutoka hapo.\
[**Maelezo zaidi kwenye ukurasa wa unconstrained delegation**](unconstrained-delegation.md).

### CredSSP

Njia nyingine ya kuepuka tatizo hili ambayo ni [**isiyo salama sana**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) ni **Mtoa Huduma wa Usalama wa Akili**. Kutoka Microsoft:

> Uthibitishaji wa CredSSP unapeleka akili za mtumiaji kutoka kwenye kompyuta ya ndani hadi kwenye kompyuta ya mbali. Praktiki hii inaongeza hatari ya usalama wa operesheni ya mbali. Ikiwa kompyuta ya mbali imevunjwa, wakati akili zinapopelekwa kwake, akili zinaweza kutumika kudhibiti kikao cha mtandao.

Inapendekezwa sana kwamba **CredSSP** izuiwe kwenye mifumo ya uzalishaji, mitandao nyeti, na mazingira kama hayo kutokana na wasiwasi wa usalama. Ili kubaini ikiwa **CredSSP** imewezeshwa, amri ya `Get-WSManCredSSP` inaweza kukimbizwa. Amri hii inaruhusu **kuangalia hali ya CredSSP** na inaweza hata kutekelezwa kwa mbali, ikiwa **WinRM** imewezeshwa.
```powershell
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
## Workarounds

### Invoke Command

Ili kushughulikia tatizo la double hop, njia inayohusisha `Invoke-Command` iliyozungushwa inawasilishwa. Hii haisuluhishi tatizo moja kwa moja lakini inatoa suluhisho mbadala bila kuhitaji usanidi maalum. Njia hii inaruhusu kutekeleza amri (`hostname`) kwenye seva ya pili kupitia amri ya PowerShell inayotekelezwa kutoka kwenye mashine ya awali ya shambulio au kupitia PS-Session iliyowekwa awali na seva ya kwanza. Hapa kuna jinsi inavyofanywa:
```powershell
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Kwa upande mwingine, kuanzisha PS-Session na seva ya kwanza na kuendesha `Invoke-Command` kwa kutumia `$cred` inapendekezwa kwa kuunganisha kazi.

### Sajili Mipangilio ya PSSession

Suluhisho la kupita tatizo la double hop linahusisha kutumia `Register-PSSessionConfiguration` na `Enter-PSSession`. Njia hii inahitaji mbinu tofauti na `evil-winrm` na inaruhusu kikao ambacho hakikabiliwi na kikomo cha double hop.
```powershell
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
klist
```
### PortForwarding

Kwa wasimamizi wa ndani kwenye lengo la kati, upitishaji wa bandari unaruhusu maombi kutumwa kwa seva ya mwisho. Kwa kutumia `netsh`, sheria inaweza kuongezwa kwa upitishaji wa bandari, pamoja na sheria ya moto ya Windows kuruhusu bandari iliyopitishwa.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` inaweza kutumika kwa ajili ya kupeleka maombi ya WinRM, labda kama chaguo ambalo halionekani sana ikiwa ufuatiliaji wa PowerShell ni wasiwasi. Amri iliyo hapa chini inaonyesha matumizi yake:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

Kuweka OpenSSH kwenye seva ya kwanza kunaruhusu suluhisho kwa tatizo la double-hop, hasa muhimu kwa hali za jump box. Njia hii inahitaji usakinishaji wa CLI na usanidi wa OpenSSH kwa Windows. Wakati imewekwa kwa Uthibitishaji wa Nywila, hii inaruhusu seva ya kati kupata TGT kwa niaba ya mtumiaji.

#### Hatua za Usakinishaji wa OpenSSH

1. Pakua na hamasisha toleo la hivi karibuni la OpenSSH zip kwenye seva lengwa.
2. Fungua na endesha script ya `Install-sshd.ps1`.
3. Ongeza sheria ya firewall kufungua bandari 22 na thibitisha huduma za SSH zinaendesha.

Ili kutatua makosa ya `Connection reset`, ruhusa zinaweza kuhitaji kusasishwa ili kuruhusu kila mtu kuwa na ufikiaji wa kusoma na kutekeleza kwenye saraka ya OpenSSH.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
## References

* [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
* [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
* [https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting)
* [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
Jifunze & fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze & fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **fuata** sisi kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
