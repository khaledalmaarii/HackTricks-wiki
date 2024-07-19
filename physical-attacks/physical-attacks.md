# Mashambulizi ya Kimwili

{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuatilie** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ni injini ya utafutaji inayotumiwa na **dark-web** ambayo inatoa kazi za **bure** za kuangalia ikiwa kampuni au wateja wake wamekuwa **wameathiriwa** na **stealer malwares**.

Lengo lao kuu la WhiteIntel ni kupambana na kuchukuliwa kwa akaunti na mashambulizi ya ransomware yanayotokana na malware inayopora taarifa.

Unaweza kuangalia tovuti yao na kujaribu injini yao **bure** kwenye:

{% embed url="https://whiteintel.io" %}

---

## Urejeleaji wa Nenosiri la BIOS na Usalama wa Mfumo

**Kurekebisha BIOS** kunaweza kufanywa kwa njia kadhaa. Karamu nyingi za mama zina **betri** ambayo, ikiondolewa kwa takriban **dakika 30**, itarejesha mipangilio ya BIOS, ikiwa ni pamoja na nenosiri. Vinginevyo, **jumper kwenye karamu ya mama** inaweza kubadilishwa ili kurejesha mipangilio hii kwa kuunganisha pini maalum.

Kwa hali ambapo marekebisho ya vifaa hayawezekani au si ya vitendo, **zana za programu** zinatoa suluhisho. Kuendesha mfumo kutoka kwa **Live CD/USB** na usambazaji kama **Kali Linux** kunatoa ufikiaji wa zana kama **_killCmos_** na **_CmosPWD_**, ambazo zinaweza kusaidia katika urejeleaji wa nenosiri la BIOS.

Katika matukio ambapo nenosiri la BIOS halijulikani, kuingiza kwa makosa **maradufu tatu** kawaida husababisha nambari ya kosa. Nambari hii inaweza kutumika kwenye tovuti kama [https://bios-pw.org](https://bios-pw.org) ili kupata nenosiri linaloweza kutumika.

### Usalama wa UEFI

Kwa mifumo ya kisasa inayotumia **UEFI** badala ya BIOS ya jadi, zana **chipsec** inaweza kutumika kuchambua na kubadilisha mipangilio ya UEFI, ikiwa ni pamoja na kuzima **Secure Boot**. Hii inaweza kufanywa kwa amri ifuatayo:

`python chipsec_main.py -module exploits.secure.boot.pk`

### Uchambuzi wa RAM na Mashambulizi ya Cold Boot

RAM huhifadhi data kwa muda mfupi baada ya nguvu kukatwa, kawaida kwa **dakika 1 hadi 2**. Ustahimilivu huu unaweza kupanuliwa hadi **dakika 10** kwa kutumia vitu baridi, kama nitrojeni ya kioevu. Wakati wa kipindi hiki kirefu, **memory dump** inaweza kuundwa kwa kutumia zana kama **dd.exe** na **volatility** kwa uchambuzi.

### Mashambulizi ya Upatikanaji wa Kumbukumbu ya Moja kwa Moja (DMA)

**INCEPTION** ni zana iliyoundwa kwa ajili ya **manipulation ya kumbukumbu ya kimwili** kupitia DMA, inayofaa na interfaces kama **FireWire** na **Thunderbolt**. Inaruhusu kupita taratibu za kuingia kwa kubadilisha kumbukumbu ili kukubali nenosiri lolote. Hata hivyo, haiwezi kufanya kazi dhidi ya mifumo ya **Windows 10**.

### Live CD/USB kwa Ufikiaji wa Mfumo

Kubadilisha binaries za mfumo kama **_sethc.exe_** au **_Utilman.exe_** kwa nakala ya **_cmd.exe_** kunaweza kutoa dirisha la amri lenye mamlaka ya mfumo. Zana kama **chntpw** zinaweza kutumika kuhariri faili ya **SAM** ya usakinishaji wa Windows, kuruhusu mabadiliko ya nenosiri.

**Kon-Boot** ni zana inayorahisisha kuingia kwenye mifumo ya Windows bila kujua nenosiri kwa kubadilisha kwa muda kernel ya Windows au UEFI. Taarifa zaidi zinaweza kupatikana kwenye [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

### Kushughulikia Vipengele vya Usalama wa Windows

#### Mifupisho ya Boot na Urejeleaji

- **Supr**: Fikia mipangilio ya BIOS.
- **F8**: Ingia katika hali ya Urejeleaji.
- Kubonyeza **Shift** baada ya bendera ya Windows kunaweza kupita autologon.

#### Vifaa vya BAD USB

Vifaa kama **Rubber Ducky** na **Teensyduino** vinatumika kama majukwaa ya kuunda **bad USB** vifaa, vinavyoweza kutekeleza payload zilizowekwa awali zinapounganishwa na kompyuta lengwa.

#### Nakala ya Kivolumu Kivuli

Mamlaka ya msimamizi yanaruhusu kuunda nakala za faili nyeti, ikiwa ni pamoja na faili ya **SAM**, kupitia PowerShell.

### Kupita Usimbaji wa BitLocker

Usimbaji wa BitLocker unaweza kupitishwa ikiwa **nenosiri la urejeleaji** linapatikana ndani ya faili ya memory dump (**MEMORY.DMP**). Zana kama **Elcomsoft Forensic Disk Decryptor** au **Passware Kit Forensic** zinaweza kutumika kwa kusudi hili.

### Uhandisi wa Kijamii kwa Kuongeza Nenosiri la Urejeleaji

Nenosiri jipya la urejeleaji la BitLocker linaweza kuongezwa kupitia mbinu za uhandisi wa kijamii, kumshawishi mtumiaji kutekeleza amri inayoongeza nenosiri jipya lililotengenezwa kwa sifuri, hivyo kurahisisha mchakato wa ufichuzi.

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ni injini ya utafutaji inayotumiwa na **dark-web** ambayo inatoa kazi za **bure** za kuangalia ikiwa kampuni au wateja wake wamekuwa **wameathiriwa** na **stealer malwares**.

Lengo lao kuu la WhiteIntel ni kupambana na kuchukuliwa kwa akaunti na mashambulizi ya ransomware yanayotokana na malware inayopora taarifa.

Unaweza kuangalia tovuti yao na kujaribu injini yao **bure** kwenye:

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuatilie** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
