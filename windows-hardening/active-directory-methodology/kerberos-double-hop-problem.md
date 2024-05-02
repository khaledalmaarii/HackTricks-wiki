# Tatizo la Mara Mbili la Kerberos

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Unataka kuona **kampuni yako ikionyeshwa kwenye HackTricks**? au unataka kupata upatikanaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **nifuata** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Utangulizi

Tatizo la "Mara Mbili" la Kerberos hutokea wakati muhusika anajaribu kutumia **uthibitisho wa Kerberos kupitia** **hops** mbili, kwa mfano kutumia **PowerShell**/**WinRM**.

Wakati **uthibitisho** unapotokea kupitia **Kerberos**, **siri** **hazihifadhiwi** kwenye **kumbukumbu**. Hivyo, ikiwa unatumia mimikatz hutapata **siri** za mtumiaji kwenye mashine hata kama anatekeleza michakato.

Hii ni kwa sababu wakati unapounganisha na Kerberos hatua zifuatazo hufanyika:

1. User1 hutoa siri na **domain controller** hurudisha **TGT** ya Kerberos kwa User1.
2. User1 anatumia **TGT** kuomba **tiketi ya huduma** ili **kuunganisha** kwenye Seva1.
3. User1 **anaunganisha** kwenye **Seva1** na kutoa **tiketi ya huduma**.
4. **Seva1** **haina** **siri** za User1 zilizohifadhiwa au **TGT** ya User1. Kwa hivyo, wakati User1 kutoka Seva1 anapojaribu kuingia kwenye seva ya pili, hawezi **kuthibitishwa**.

### Uteuzi Usiozuiliwa

Ikiwa **uteuzi usiozuiliwa** umewezeshwa kwenye PC, hii haitatokea kwani **Seva** itapata **TGT** ya kila mtumiaji anayeipata. Zaidi ya hayo, ikiwa uteuzi usiozuiliwa unatumika labda unaweza **kuhatarisha Msimamizi wa Kikoa** kutoka hapo.\
[Maelezo zaidi kwenye ukurasa wa uteuzi usiozuiliwa](unconstrained-delegation.md).

### CredSSP

Njia nyingine ya kuepuka tatizo hili ambayo ni [**si salama sana**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) ni **Mtoaji wa Usaidizi wa Usalama wa Siri**. Kutoka kwa Microsoft:

> Uthibitisho wa CredSSP unaweka siri za mtumiaji kutoka kwenye kompyuta ya ndani kwenda kwenye kompyuta ya mbali. Mazoea haya huongeza hatari ya usalama wa operesheni ya mbali. Ikiwa kompyuta ya mbali itadhuriwa, wakati siri zinapopitishwa kwake, siri hizo zinaweza kutumika kudhibiti kikao cha mtandao.

Inashauriwa sana kwamba **CredSSP** izimwe kwenye mifumo ya uzalishaji, mitandao inayohitaji usiri, na mazingira kama hayo kutokana na wasiwasi wa usalama. Ili kubaini ikiwa **CredSSP** imezimwa, amri ya `Get-WSManCredSSP` inaweza kutekelezwa. Amri hii inaruhusu **uchunguzi wa hali ya CredSSP** na inaweza hata kutekelezwa kijijini, ikiruhusiwa **WinRM** iwezeshwe.
```powershell
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
## Njia za Kuzunguka

### Amuru Amri

Ili kushughulikia shida ya mara mbili ya kupita, njia inayohusisha `Invoke-Command` iliyonakiliwa inapendekezwa. Hii haishughulikii shida moja kwa moja lakini inatoa suluhisho mbadala bila kuhitaji mipangilio maalum. Mbinu hii inaruhusu kutekeleza amri (`jina la mwenyeji`) kwenye seva ya pili kupitia amri ya PowerShell iliyotekelezwa kutoka kwa mashine ya kwanza ya kushambulia au kupitia kikao cha PS kilichoundwa hapo awali na seva ya kwanza. Hivi ndivyo inavyofanywa:
```powershell
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
### Kuanzisha Usajili wa Mipangilio ya PSSession

Lahaja ya kuepuka tatizo la mara mbili linajumuisha kutumia `Register-PSSessionConfiguration` pamoja na `Enter-PSSession`. Mbinu hii inahitaji njia tofauti kuliko `evil-winrm` na inaruhusu kikao ambacho hakisumbuliwi na kizuizi cha mara mbili.
```powershell
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
klist
```
### PortForwarding

Kwa waendeshaji wa ndani kwenye lengo la kati, kupeleka bandari inaruhusu maombi kutumwa kwa seva ya mwisho. Kwa kutumia `netsh`, sheria inaweza kuongezwa kwa ajili ya kupeleka bandari, pamoja na sheria ya firewall ya Windows kuruhusu bandari iliyopelekwa.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` inaweza kutumika kwa kusafirisha maombi ya WinRM, labda kama chaguo linaloweza kugundulika kidogo ikiwa ufuatiliaji wa PowerShell unahusika. Amri hapa chini inaonyesha matumizi yake:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

Kuweka OpenSSH kwenye server ya kwanza inawezesha suluhisho la shida ya double-hop, hasa inayofaa kwa mazingira ya jump box. Mbinu hii inahitaji ufungaji wa CLI na usanidi wa OpenSSH kwa Windows. Wakati ilipowekwa kwa Uthibitishaji wa Nywila, hii inaruhusu server ya kati kupata TGT kwa niaba ya mtumiaji.

#### Hatua za Ufungaji wa OpenSSH

1. Pakua na hamisha zip ya toleo jipya la OpenSSH kwenye server ya lengo.
2. Fungua na endesha script ya `Install-sshd.ps1`.
3. Ongeza sheria ya firewall kufungua bandari 22 na thibitisha huduma za SSH zinaendeshwa.

Ili kutatua makosa ya `Connection reset`, ruhusa inaweza kuhitaji kusasishwa kuruhusu kila mtu kusoma na kutekeleza upatikanaji kwenye saraka ya OpenSSH.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
## Marejeo

* [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
* [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
* [https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting)
* [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Jifunze kuhack AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Je unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, unataka kuona **kampuni yako ikionyeshwa kwenye HackTricks**? au unataka kupata upatikanaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **fuata** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwenye** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
