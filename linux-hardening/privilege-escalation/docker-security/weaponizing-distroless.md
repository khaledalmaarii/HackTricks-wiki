# Kutumia Distroless kama Silaha

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Distroless ni Nini

Chombo cha distroless ni aina ya chombo ambacho **kinajumuisha tu tegemezi muhimu za kuendesha programu fulani**, bila programu au zana zingine zisizohitajika. Vyombo hivi vimeundwa kuwa **nyepesi** na **salama** iwezekanavyo, na lengo lake ni **kupunguza eneo la shambulio** kwa kuondoa sehemu zisizohitajika.

Vyombo vya distroless mara nyingi hutumiwa katika **mazingira ya uzalishaji ambapo usalama na uaminifu ni muhimu**.

Baadhi ya **mifano** ya **vyombo vya distroless** ni:

* Iliyotolewa na **Google**: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
* Iliyotolewa na **Chainguard**: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Kutumia Distroless kama Silaha

Lengo la kutumia chombo cha distroless kama silaha ni kuweza **kutekeleza programu na malipo yoyote hata na vikwazo** vilivyotokana na **distroless** (ukosefu wa programu za kawaida katika mfumo) na pia ulinzi unaopatikana kawaida katika vyombo kama vile **soma tu** au **isitekeleze** katika `/dev/shm`.

### Kupitia Kumbukumbu

Inakuja wakati fulani wa 2023...

### Kupitia Programu Zilizopo

#### openssl

****[**Katika chapisho hili,**](https://www.form3.tech/engineering/content/exploiting-distroless-images) imeelezewa kuwa programu ya **`openssl`** mara nyingi hupatikana katika vyombo hivi, labda kwa sababu inahitajika na programu ambayo itaendeshwa ndani ya chombo.

Kwa kutumia programu ya **`openssl`** ni iwezekanavyo kutekeleza mambo yoyote.
