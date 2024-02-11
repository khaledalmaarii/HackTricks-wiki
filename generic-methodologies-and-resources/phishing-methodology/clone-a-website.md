<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>


Kwa tathmini ya phishing mara nyingine inaweza kuwa na manufaa kuiga kabisa **tovuti**.

Kumbuka kuwa unaweza pia kuongeza baadhi ya mzigo kwenye tovuti iliyoigwa kama kitanzi cha BeEF ili "kudhibiti" kichupo cha mtumiaji.

Kuna zana tofauti unazoweza kutumia kwa kusudi hili:

## wget
```text
wget -mk -nH
```
## goclone

Goclone ni chombo cha barua pepe kinachotumiwa kwa kuchukua tovuti halisi na kuunda nakala yake ili kuunda tovuti bandia. Chombo hiki kinaweza kutumiwa kwa njia mbaya kwa kutekeleza mbinu ya ulaghai inayojulikana kama "phishing". 

Kwa kuanza, unahitaji kufunga Goclone kwenye mfumo wako. Unaweza kufanya hivyo kwa kufuata hatua zifuatazo:

1. Pakua Goclone kutoka kwenye chanzo chake rasmi au kutumia amri ifuatayo ya Terminal:

   ```
   go get github.com/RedTeamPentesting/goclone
   ```

2. Baada ya kufunga Goclone, unaweza kuitumia kwa kufuata amri ifuatayo ya Terminal:

   ```
   goclone -u <URL ya tovuti ya asili> -o <jina la folda ya tovuti bandia>
   ```

   Kwa mfano, ikiwa unataka kuiga tovuti ya Facebook, unaweza kutumia amri ifuatayo:

   ```
   goclone -u https://www.facebook.com -o facebook-clone
   ```

   Hii itasababisha Goclone kuiga tovuti ya Facebook na kuunda nakala yake kwenye folda iliyopewa jina "facebook-clone".

Baada ya kuiga tovuti, unaweza kuitumia kwa njia mbaya kwa kutekeleza shambulio la ulaghai. Ni muhimu kukumbuka kuwa matumizi mabaya ya Goclone ni kinyume cha sheria na inaweza kusababisha mashtaka ya kisheria. Ni muhimu kuzingatia sheria na kufanya matumizi sahihi ya zana hii.
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## Zana za Uhandisi wa Jamii

### Kigezo cha Kujifanya

Kigezo cha kujifanya ni zana muhimu katika uhandisi wa kijamii. Inaruhusu mtumiaji kuiga tovuti halisi na kuunda nakala yake. Hii ni njia ya kawaida ya kutekeleza mashambulizi ya kudanganya na kuiba habari za siri kutoka kwa watumiaji wasio na ufahamu.

#### Hatua za Kujifanya Tovuti

1. Chagua tovuti ya kulenga: Chagua tovuti ambayo ungependa kuiga. Inashauriwa kuchagua tovuti maarufu ambayo inavutia idadi kubwa ya watumiaji.

2. Pakua kigezo cha tovuti: Tafuta kigezo cha tovuti kinachofanana na tovuti unayotaka kuiga. Kuna vyanzo vingi vya kigezo cha tovuti vinavyopatikana mkondoni.

3. Fanya mabadiliko kwenye kigezo: Baada ya kupakua kigezo cha tovuti, fanya mabadiliko kulingana na mahitaji yako. Unaweza kubadilisha picha, maandishi, na viungo ili kuifanya iwe sawa na tovuti halisi.

4. Weka kigezo kwenye seva: Baada ya kufanya mabadiliko yote, weka kigezo kwenye seva yako ili iweze kupatikana mkondoni.

5. Tuma kiunga kwa lengo lako: Sasa unaweza kutuma kiunga cha kigezo chako kwa lengo lako. Unaweza kutumia njia mbalimbali kama barua pepe, ujumbe wa maandishi, au mitandao ya kijamii.

6. Shughulikia habari zilizopatikana: Mara tu lengo lako linapofungua kiunga na kuingia habari zao za siri, habari hizo zitatumwa kwako. Unaweza kuzitumia kwa madhumuni yako ya kudanganya au kuiba habari.

Kumbuka: Kujifanya tovuti ni shughuli haramu na inaweza kusababisha mashtaka ya kisheria. Tumia maarifa haya kwa uwajibikaji na kwa madhumuni ya kujifunza tu.
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
