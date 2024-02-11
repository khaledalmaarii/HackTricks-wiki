# Tatizo la Mara Mbili la Kerberos

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? Au ungependa kupata **toleo jipya zaidi la PEASS au kupakua HackTricks kwa muundo wa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuatilie** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwenye** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Utangulizi

Tatizo la "Mara Mbili" la Kerberos linatokea wakati mshambuliaji anajaribu kutumia **uthibitisho wa Kerberos kupitia hatua mbili**, kwa mfano kwa kutumia **PowerShell**/**WinRM**.

Wakati **uthibitisho** unapotokea kupitia **Kerberos**, **vyeti** **havihifadhiwi** kwenye **kumbukumbu**. Kwa hiyo, ikiwa unatumia mimikatz hutapata vyeti vya mtumiaji kwenye kompyuta hata kama anatumia michakato.

Hii ni kwa sababu wakati unapojiunganisha na Kerberos hatua zifuatazo hufanyika:

1. User1 hutoa vyeti na **kudhibitiwa kwa kikoa** hurudisha **TGT** ya Kerberos kwa User1.
2. User1 anatumia **TGT** kuomba **cheti cha huduma** ili **kuunganisha** na Server1.
3. User1 **anaunganisha** na **Server1** na hutoa **cheti cha huduma**.
4. **Server1** **haina** vyeti vya User1 vilivyohifadhiwa au **TGT** ya User1. Kwa hiyo, wakati User1 kutoka Server1 anajaribu kuingia kwenye seva ya pili, hawezi **kuthibitisha kitambulisho**.

### Utekelezaji Usiozuiliwa

Ikiwa **utekelezaji usiozuiliwa** umewezeshwa kwenye PC, hii haitatokea kwani **Seva** itapata **TGT** ya kila mtumiaji anayeiingia. Zaidi ya hayo, ikiwa utekelezaji usiozuiliwa unatumika, labda unaweza **kudhoofisha Kudhibiti Kikoa** kutoka hapo.\
[**Maelezo zaidi katika ukurasa wa utekelezaji usiozuiliwa**](unconstrained-delegation.md).

### CredSSP

Njia nyingine ya kuepuka tatizo hili ambayo ni [**hatari sana**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) ni **Mtoa Msaada wa Usalama wa Kitambulisho**. Kutoka kwa Microsoft:

> Uthibitisho wa CredSSP huruhusu uthibitisho wa kitambulisho cha mtumiaji kutoka kwenye kompyuta ya ndani kwenda kwenye kompyuta ya mbali. Mazoea haya huongeza hatari ya usalama ya operesheni ya mbali. Ikiwa kompyuta ya mbali imevamiwa, vyeti vinapopitishwa kwake, vyeti vinaweza kutumika kudhibiti kikao cha mtandao.

Inashauriwa sana kwamba **CredSSP** iwe imelemazwa kwenye mifumo ya uzalishaji, mitandao yenye hisia, na mazingira kama hayo kutokana na wasiwasi wa usalama. Ili kujua ikiwa **CredSSP** imezimwa, amri ya `Get-WSManCredSSP` inaweza kukimbia. Amri hii inaruhusu **uchunguzi wa hali ya CredSSP** na inaweza hata kutekelezwa kwa mbali, ikiwa **WinRM** imezimwa.
```powershell
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
## Njia za Kuzunguka

### Kuita Amri

Ili kushughulikia tatizo la double hop, njia inayohusisha `Invoke-Command` iliyopachikwa imeonyeshwa. Hii haishughulikii tatizo moja kwa moja lakini inatoa njia ya kuzunguka bila kuhitaji mipangilio maalum. Njia hii inaruhusu kutekeleza amri (`hostname`) kwenye seva ya pili kupitia amri ya PowerShell iliyotekelezwa kutoka kwenye kifaa cha kwanza cha kushambulia au kupitia PS-Session iliyowekwa hapo awali na seva ya kwanza. Hapa kuna jinsi ya kufanya hivyo:
```powershell
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Kwa upande mwingine, inapendekezwa kuweka PS-Session na server ya kwanza na kukimbia `Invoke-Command` kwa kutumia `$cred` ili kusambaza kazi.

### Jisajili kwa PSSession Configuration

Suluhisho la kuepuka tatizo la double hop linahusisha kutumia `Register-PSSessionConfiguration` na `Enter-PSSession`. Njia hii inahitaji njia tofauti na `evil-winrm` na inaruhusu kikao ambacho hakipatwi na kizuizi cha double hop.
```powershell
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
klist
```
### PortForwarding

Kwa waendeshaji wa ndani kwenye lengo la kati, kuwezesha mbele ya bandari kunaruhusu maombi kutumwa kwa seva ya mwisho. Kwa kutumia `netsh`, sheria inaweza kuongezwa kwa ajili ya kuwezesha mbele ya bandari, pamoja na sheria ya Windows firewall kuruhusu bandari iliyowezeshwa.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` inaweza kutumika kwa ajili ya kusambaza maombi ya WinRM, ikiwa ni chaguo linaloweza kugundulika kidogo ikiwa ufuatiliaji wa PowerShell ni wasiwasi. Amri ifuatayo inaonyesha matumizi yake:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

Kuweka OpenSSH kwenye seva ya kwanza kunawezesha suluhisho la tatizo la double-hop, hasa linapokuwa na umuhimu katika mazingira ya jump box. Njia hii inahitaji ufungaji na usanidi wa OpenSSH kwa njia ya CLI kwenye Windows. Wakati inapowekwa kwa Uthibitishaji wa Nenosiri, hii inaruhusu seva ya kati kupata TGT kwa niaba ya mtumiaji.

#### Hatua za Ufungaji wa OpenSSH

1. Pakua na hamisha faili ya hivi karibuni ya OpenSSH kwenye seva ya lengo.
2. Fungua faili na endesha skripti ya `Install-sshd.ps1`.
3. Ongeza sheria ya firewall ili kufungua bandari 22 na hakikisha huduma za SSH zinaendesha.

Ili kutatua makosa ya `Connection reset`, inaweza kuwa ni lazima kusasisha ruhusa ili kuruhusu kila mtu kupata haki ya kusoma na kutekeleza kwenye saraka ya OpenSSH.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
## Marejeo

* [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
* [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
* [https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting)
* [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? Au ungependa kupata ufikiaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuate** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
