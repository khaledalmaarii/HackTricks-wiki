# Mashambulizi ya Kimwili

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Kurejesha Nenosiri la BIOS na Usalama wa Mfumo

**Kurejesha BIOS** kunaweza kufanikiwa kwa njia kadhaa. Zaidi ya hayo, motherboard nyingi zina **betri** ambayo, ikiondolewa kwa takriban **dakika 30**, itarejesha mipangilio ya BIOS, ikiwa ni pamoja na nenosiri. Kwa njia mbadala, **jumper kwenye motherboard** inaweza kurekebishwa ili kurejesha mipangilio hii kwa kuunganisha pini maalum.

Katika hali ambapo marekebisho ya vifaa sio rahisi au haiwezekani, zana za **programu** zinatoa suluhisho. Kuendesha mfumo kutoka kwenye **CD/USB ya Moja kwa Moja** na usambazaji kama vile **Kali Linux** hutoa ufikiaji wa zana kama **_killCmos_** na **_CmosPWD_**, ambazo zinaweza kusaidia katika kurejesha nenosiri la BIOS.

Katika hali ambapo nenosiri la BIOS halijulikani, kuingiza kwa makosa **mara tatu** kwa kawaida kutatokea kosa. Nambari hii inaweza kutumika kwenye tovuti kama [https://bios-pw.org](https://bios-pw.org) ili kupata nenosiri linaloweza kutumiwa.

### Usalama wa UEFI

Kwa mifumo ya kisasa inayotumia **UEFI** badala ya BIOS ya jadi, zana ya **chipsec** inaweza kutumika kuchambua na kurekebisha mipangilio ya UEFI, ikiwa ni pamoja na kulemaza **Secure Boot**. Hii inaweza kufanikiwa kwa kutumia amri ifuatayo:

`python chipsec_main.py -module exploits.secure.boot.pk`

### Uchambuzi wa RAM na Mashambulizi ya Cold Boot

RAM inahifadhi data kwa muda mfupi baada ya umeme kukatwa, kawaida kwa muda wa **dakika 1 hadi 2**. Uhai huu unaweza kuongezwa hadi **dakika 10** kwa kutumia vitu baridi, kama vile nitrojeni ya majimaji. Wakati wa kipindi hiki kirefu, **kumbukumbu ya kumbukumbu** inaweza kuundwa kwa kutumia zana kama **dd.exe** na **volatility** kwa ajili ya uchambuzi.

### Mashambulizi ya Upatikanaji wa Moja kwa Moja wa Kumbukumbu (DMA)

**INCEPTION** ni zana iliyoundwa kwa ajili ya **udanganyifu wa kumbukumbu ya kimwili** kupitia DMA, inayofaa kwa interfaces kama vile **FireWire** na **Thunderbolt**. Inaruhusu kuepuka taratibu za kuingia kwa kurekebisha kumbukumbu ili kukubali nenosiri lolote. Hata hivyo, haifanyi kazi kwa mifumo ya **Windows 10**.

### CD/USB ya Moja kwa Moja kwa Upatikanaji wa Mfumo

Kubadilisha faili za mfumo kama vile **_sethc.exe_** au **_Utilman.exe_** na nakala ya **_cmd.exe_** inaweza kutoa dirisha la amri na mamlaka ya mfumo. Zana kama **chntpw** zinaweza kutumika kuhariri faili ya **SAM** ya ufungaji wa Windows, kuruhusu mabadiliko ya nenosiri.

**Kon-Boot** ni zana inayorahisisha kuingia kwenye mifumo ya Windows bila kujua nenosiri kwa muda mfupi kwa kurekebisha muda mfupi wa Windows au UEFI. Taarifa zaidi zinaweza kupatikana kwenye [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

### Kushughulikia Vipengele vya Usalama vya Windows

#### Vifupisho vya Kuanza na Kurejesha

- **Supr**: Fikia mipangilio ya BIOS.
- **F8**: Ingia kwenye hali ya Kurejesha.
- Kubonyeza **Shift** baada ya bango la Windows kunaweza kuepuka kuingia moja kwa moja.

#### Vifaa vya BAD USB

Vifaa kama **Rubber Ducky** na **Teensyduino** hutumika kama majukwaa ya kuunda vifaa vya **bad USB**, vinavyoweza kutekeleza malipo yaliyopangwa kabla wakati vinapounganishwa na kompyuta ya lengo.

#### Nakala ya Kivuli cha Kiasi

Mamlaka ya msimamizi inaruhusu uundaji wa nakala za faili nyeti, ikiwa ni pamoja na faili ya **SAM**, kupitia PowerShell.

### Kuepuka Ufichuzi wa BitLocker

Ufichaji wa BitLocker unaweza kuepukwa ikiwa **nenosiri la urejeshaji** linapatikana ndani ya faili ya kumbukumbu ya kumbukumbu (**MEMORY.DMP**). Zana kama **Elcomsoft Forensic Disk Decryptor** au **Passware Kit Forensic** zinaweza kutumika kwa kusudi hili.

### Uhandisi wa Jamii kwa Kuongeza Funguo za Urejeshaji

Funguo mpya za urejeshaji wa BitLocker zinaweza kuongezwa kupitia mbinu za uhandisi wa jamii, kwa kuwashawishi watumiaji kutekeleza amri ambayo inaongeza funguo mpya za urejeshaji zilizoundwa na sifuri, hivyo kusaidia mchakato wa kufuta ufichaji.

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
