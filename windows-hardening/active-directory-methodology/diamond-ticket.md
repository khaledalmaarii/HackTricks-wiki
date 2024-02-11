# Tiketi ya Almasi

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana katika HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Tiketi ya Almasi

**Kama tiketi ya dhahabu**, tiketi ya almasi ni TGT ambayo inaweza kutumika kufikia huduma yoyote kama mtumiaji yeyote. Tiketi ya dhahabu inatengenezwa kabisa nje ya mtandao, imefichwa kwa kutumia hash ya krbtgt ya kikoa hicho, na kisha inapitishwa kwenye kikao cha kuingia ili kutumika. Kwa sababu watumiaji wa kikoa hawafuatilii TGTs ambazo wamezitoa kwa halali, wataikubali kwa furaha TGTs ambazo zimefichwa na hash yao ya krbtgt.

Kuna njia mbili za kawaida za kugundua matumizi ya tiketi za dhahabu:

* Tafuta TGS-REQs ambazo hazina AS-REQ inayolingana.
* Tafuta TGTs ambazo zina thamani za kipumbavu, kama vile muda wa maisha wa miaka 10 wa chaguo-msingi wa Mimikatz.

Tiketi ya almasi inatengenezwa kwa **kubadilisha sehemu za TGT halali ambayo ilitolewa na DC**. Hii inafanikiwa kwa **kuomba** TGT, **kuidondosha** na hash ya krbtgt ya kikoa, **kubadilisha** sehemu zinazohitajika za tiketi, kisha **kuifichua tena**. Hii **inaondoa kasoro mbili zilizotajwa hapo juu** za tiketi ya dhahabu kwa sababu:

* TGS-REQs zitakuwa na AS-REQ inayotangulia.
* TGT ilitolewa na DC ambayo inamaanisha itakuwa na maelezo sahihi yote kutoka kwa sera ya Kerberos ya kikoa. Ingawa haya yanaweza kughushiwa kwa usahihi katika tiketi ya dhahabu, ni ngumu zaidi na inaweza kusababisha makosa.
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
<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
