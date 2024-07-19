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


Kuna blogu kadhaa kwenye Mtandao ambazo **zinabainisha hatari za kuacha printers zikiwa zimewekwa na LDAP zikiwa na** akauti za kuingia za kawaida/dhaifu.\
Hii ni kwa sababu mshambuliaji anaweza **kudanganya printer kujiandikisha dhidi ya seva ya LDAP isiyo halali** (kawaida `nc -vv -l -p 444` inatosha) na kukamata **akauti za printer kwa maandiko wazi**.

Pia, printers kadhaa zitakuwa na **kumbukumbu za majina ya watumiaji** au zinaweza hata kuwa na uwezo wa **kupakua majina yote ya watumiaji** kutoka kwa Domain Controller.

Taarifa hii **nyeti** na **ukosefu wa usalama** wa kawaida inafanya printers kuwa za kuvutia sana kwa washambuliaji.

Baadhi ya blogu kuhusu mada hiyo:

* [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
* [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

## Printer Configuration
- **Location**: Orodha ya seva ya LDAP inapatikana kwenye: `Network > LDAP Setting > Setting Up LDAP`.
- **Behavior**: Kiolesura kinaruhusu mabadiliko ya seva ya LDAP bila kuingiza tena akauti, ikilenga urahisi wa mtumiaji lakini ikileta hatari za usalama.
- **Exploit**: Ulaghai unahusisha kuelekeza anwani ya seva ya LDAP kwa mashine iliyo chini ya udhibiti na kutumia kipengele cha "Test Connection" kukamata akauti.

## Capturing Credentials

**Kwa hatua za kina zaidi, rejelea [chanzo](https://grimhacker.com/2018/03/09/just-a-printer/).**

### Method 1: Netcat Listener
Mkusanyiko rahisi wa netcat unaweza kutosha:
```bash
sudo nc -k -v -l -p 386
```
Hata hivyo, mafanikio ya mbinu hii yanatofautiana.

### Method 2: Full LDAP Server with Slapd
Njia ya kuaminika zaidi inahusisha kuanzisha seva kamili ya LDAP kwa sababu printer inafanya null bind ikifuatiwa na uchunguzi kabla ya kujaribu kuunganisha akidi.

1. **LDAP Server Setup**: Mwongozo unafuata hatua kutoka [chanzo hiki](https://www.server-world.info/en/note?os=Fedora_26&p=openldap).
2. **Key Steps**:
- Sakinisha OpenLDAP.
- Sanidi nenosiri la admin.
- Ingiza mifano ya msingi.
- Weka jina la kikoa kwenye DB ya LDAP.
- Sanidi LDAP TLS.
3. **LDAP Service Execution**: Mara tu inapoanzishwa, huduma ya LDAP inaweza kuendeshwa kwa kutumia:
```bash
slapd -d 2
```
## References
* [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)


{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuatilie** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}
