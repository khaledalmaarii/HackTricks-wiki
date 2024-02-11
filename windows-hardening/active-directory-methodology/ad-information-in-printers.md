<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inayotangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>


Kuna blogi kadhaa kwenye mtandao ambazo **zinaonyesha hatari za kuacha wachapishaji wameboreshwa na LDAP na sifa za kuingia za chaguo-msingi/dhaifu**.\
Hii ni kwa sababu mshambuliaji anaweza **kudanganya wachapishaji kuthibitisha dhidi ya seva ya LDAP ya udanganyifu** (kawaida `nc -vv -l -p 444` inatosha) na kukamata **sifa za wachapishaji kwa maandishi wazi**.

Pia, wachapishaji kadhaa watakuwa na **magogo na majina ya watumiaji** au hata wanaweza **kupakua majina yote ya watumiaji** kutoka kwa Kudhibitiwa na Kudhibitiwa na Kudhibitiwa.

Maelezo yote haya **yenye hisia** na **ukosefu wa usalama wa kawaida** hufanya wachapishaji kuwa ya kuvutia sana kwa wadukuzi.

Baadhi ya blogi kuhusu mada hiyo:

* [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
* [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

## Usanidi wa Wachapishaji
- **Mahali**: Orodha ya seva ya LDAP inapatikana kwenye: `Mtandao > Usanidi wa LDAP > Kuweka LDAP`.
- **Tabia**: Kiolesura kinawezesha marekebisho ya seva ya LDAP bila kuingiza tena sifa za kuingia, lengo likiwa ni urahisi wa mtumiaji lakini kuna hatari za usalama.
- **Kudukua**: Kudukua kunahusisha kuelekeza anwani ya seva ya LDAP kwa kompyuta iliyodhibitiwa na kutumia kipengele cha "Jaribu Uunganisho" kukamata sifa.

## Kukamata Sifa

**Kwa hatua za kina zaidi, tazama [chanzo](https://grimhacker.com/2018/03/09/just-a-printer/) asili.**

### Njia 1: Msikilizaji wa Netcat
Msikilizaji wa netcat rahisi inaweza kuwa ya kutosha:
```bash
sudo nc -k -v -l -p 386
```
Hata hivyo, mafanikio ya njia hii hutofautiana.

### Njia ya 2: Seva kamili ya LDAP na Slapd
Njia yenye uhakika zaidi inahusisha kuweka seva kamili ya LDAP kwa sababu printer hufanya null bind ikifuatiwa na utafutaji kabla ya kujaribu kuunganisha kitambulisho.

1. **Kuweka Seva ya LDAP**: Mwongozo unafuata hatua kutoka [chanzo hiki](https://www.server-world.info/en/note?os=Fedora_26&p=openldap).
2. **Hatua muhimu**:
- Sakinisha OpenLDAP.
- Sanidi nenosiri la admin.
- Ingiza skimu za msingi.
- Weka jina la kikoa kwenye DB ya LDAP.
- Sanidi LDAP TLS.
3. **Utekelezaji wa Huduma ya LDAP**: Mara baada ya kuweka, huduma ya LDAP inaweza kutekelezwa kwa kutumia:
```bash
slapd -d 2
```
## Marejeo
* [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)


<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
