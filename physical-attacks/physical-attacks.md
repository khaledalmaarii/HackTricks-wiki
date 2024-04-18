# Mashambulizi ya Kimwili

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi mtaalamu na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalamu wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ni injini ya utaftaji inayotumia **dark-web** ambayo inatoa huduma za **bure** za kuangalia ikiwa kampuni au wateja wake wameathiriwa na **malware za wizi**.

Lengo kuu la WhiteIntel ni kupambana na utekaji wa akaunti na mashambulizi ya ransomware yanayotokana na malware za kuiba habari.

Unaweza kutembelea tovuti yao na kujaribu injini yao **bure** kwa:

{% embed url="https://whiteintel.io" %}

---

## Kurejesha Nenosiri la BIOS na Usalama wa Mfumo

**Kurejesha BIOS** kunaweza kufanikiwa kwa njia kadhaa. Kwenye baadhi ya motherboard kuna **betri** ambayo, ikiondolewa kwa takriban **dakika 30**, itarejesha mipangilio ya BIOS, ikiwa ni pamoja na nenosiri. Vinginevyo, **jumper kwenye motherboard** inaweza kurekebishwa ili kurejesha mipangilio hii kwa kuunganisha pini maalum.

Katika hali ambapo marekebisho ya vifaa siwezekani au si rahisi, **zana za programu** zinatoa suluhisho. Kuendesha mfumo kutoka kwenye **CD/USB ya Moja kwa Moja** na usambazaji kama **Kali Linux** hutoa ufikivu wa zana kama **_killCmos_** na **_CmosPWD_**, ambazo zinaweza kusaidia katika kurejesha nenosiri la BIOS.

Katika hali ambapo nenosiri la BIOS halijulikani, kulipiga **mara tatu** kwa kawaida kutasababisha nambari ya kosa. Nambari hii inaweza kutumika kwenye tovuti kama [https://bios-pw.org](https://bios-pw.org) kwa matumaini ya kupata nenosiri linaloweza kutumika.

### Usalama wa UEFI

Kwa mifumo ya kisasa inayotumia **UEFI** badala ya BIOS ya jadi, zana ya **chipsec** inaweza kutumika kuchambua na kurekebisha mipangilio ya UEFI, ikiwa ni pamoja na kulemaza **Secure Boot**. Hii inaweza kufanywa kwa amri ifuatayo:

`python chipsec_main.py -module exploits.secure.boot.pk`

### Uchambuzi wa RAM na Mashambulizi ya Cold Boot

RAM inahifadhi data kwa muda mfupi baada ya umeme kukatwa, kawaida kwa muda wa **1 hadi 2 dakika**. Uimara huu unaweza kuongezwa hadi **dakika 10** kwa kutumia vitu baridi, kama vile nitrojeni ya majimaji. Wakati wa kipindi hiki kirefu, unaweza kuunda **dumpu ya kumbukumbu** kwa kutumia zana kama **dd.exe** na **volatility** kwa uchambuzi.

### Mashambulizi ya Upatikanaji wa Kumbukumbu Moja kwa Moja (DMA)

**INCEPTION** ni zana iliyoundwa kwa **udanganyifu wa kumbukumbu ya mwili** kupitia DMA, inayoweza kutumika kwenye interface kama **FireWire** na **Thunderbolt**. Inaruhusu kupitisha taratibu za kuingia kwa kurekebisha kumbukumbu ili kukubali nenosiri lolote. Hata hivyo, haina ufanisi dhidi ya mifumo ya **Windows 10**.

### CD/USB ya Moja kwa Moja kwa Upatikanaji wa Mfumo

Kubadilisha faili za mfumo kama **_sethc.exe_** au **_Utilman.exe_** na nakala ya **_cmd.exe_** inaweza kutoa dirisha la amri lenye mamlaka ya mfumo. Zana kama **chntpw** zinaweza kutumika kuhariri faili ya **SAM** ya usanidi wa Windows, kuruhusu mabadiliko ya nenosiri.

**Kon-Boot** ni zana inayorahisisha kuingia kwenye mifumo ya Windows bila kujua nenosiri kwa muda kwa kurekebisha muda mfupi wa Windows au UEFI. Taarifa zaidi inaweza kupatikana kwenye [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

### Kushughulikia Vipengele vya Usalama vya Windows

#### Vifunguo vya Kuanzisha na Kurejesha

- **Supr**: Kufikia mipangilio ya BIOS.
- **F8**: Ingia kwenye hali ya Kurejesha.
- Kupiga **Shift** baada ya bendera ya Windows kunaweza kuzidi kiotomatiki.

#### Vifaa vya BAD USB

Vifaa kama **Rubber Ducky** na **Teensyduino** hutumika kama majukwaa ya kuunda vifaa vya **USB mbaya**, vinavyoweza kutekeleza malipo yaliyopangwa awali wakati vinapounganishwa kwenye kompyuta ya lengo.

#### Nakala ya Kivuli cha Kiasi

Mamlaka ya msimamizi inaruhusu uundaji wa nakala za faili nyeti, ikiwa ni pamoja na faili ya **SAM**, kupitia PowerShell.

### Kupitisha Ufichaji wa BitLocker

Ufichaji wa BitLocker unaweza kupitishwa ikiwa **nenosiri la urejeshaji** linapatikana ndani ya faili ya dumpu ya kumbukumbu (**MEMORY.DMP**). Zana kama **Elcomsoft Forensic Disk Decryptor** au **Passware Kit Forensic** zinaweza kutumika kwa madhumuni haya.

### Uhandisi wa Kijamii kwa Kuongeza Funguo la Uokoaji

Funguo mpya la uokoaji wa BitLocker linaweza kuongezwa kupitia mbinu za uhandisi wa kijamii, kuwashawishi watumiaji kutekeleza amri ambayo inaongeza funguo mpya la uokoaji linaloundwa na sifuri, hivyo kufanya mchakato wa kufichua kuwa rahisi.

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ni injini ya utaftaji inayotumia **dark-web** ambayo inatoa huduma za **bure** za kuangalia ikiwa kampuni au wateja wake wameathiriwa na **malware za wizi**.

Lengo kuu la WhiteIntel ni kupambana na utekaji wa akaunti na mashambulizi ya ransomware yanayotokana na malware za kuiba habari.

Unaweza kutembelea tovuti yao na kujaribu injini yao **bure** kwa:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi mtaalamu na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalamu wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
