# macOS Dirty NIB

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

**Kwa maelezo zaidi kuhusu mbinu hii angalia chapisho asilia kutoka: [https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/).** Hapa kuna muhtasari:

Faili za NIB, sehemu ya mfumo wa maendeleo wa Apple, zinakusudia kufafanua **vipengele vya UI** na mwingiliano wao katika programu. Zinajumuisha vitu vilivyopangwa kama vile madirisha na vifungo, na hupakiwa wakati wa utendaji. Licha ya matumizi yao yaendelea, Apple sasa inapendekeza Storyboards kwa ajili ya uonyeshaji wa mtiririko wa UI wa kina zaidi.

### Wasiwasi wa Usalama na Faili za NIB
Ni muhimu kutambua kwamba **faili za NIB zinaweza kuwa hatari za usalama**. Zina uwezo wa **kutekeleza amri zisizo na mipaka**, na mabadiliko kwenye faili za NIB ndani ya programu hayazuia Gatekeeper kutekeleza programu hiyo, na kuleta tishio kubwa.

### Mchakato wa Uingizaji wa Dirty NIB
#### Kuunda na Kuweka Faili ya NIB
1. **Mipangilio ya Awali**:
- Unda faili mpya ya NIB kwa kutumia XCode.
- Ongeza Kitu kwenye kiolesura, ukipanga darasa lake kuwa `NSAppleScript`.
- Sanidi mali ya awali ya `source` kupitia Sifa za Wakati wa Uendeshaji Zilizofafanuliwa na Mtumiaji.

2. **Kifaa cha Kutekeleza Msimbo**:
- Mipangilio hii inaruhusu kuendesha AppleScript kwa mahitaji.
- Jumuisha kifungo ili kuamsha kitu cha `Apple Script`, hasa kuanzisha mteule wa `executeAndReturnError:`.

3. **Kujaribu**:
- Msimbo rahisi wa Apple Script kwa ajili ya majaribio:
```bash
set theDialogText to "PWND"
display dialog theDialogText
```
- Jaribu kwa kuendesha kwenye debugger ya XCode na kubofya kifungo.

#### Kulenga Programu (Mfano: Pages)
1. **Maandalizi**:
- Nakili programu lengwa (mfano, Pages) kwenye saraka tofauti (mfano, `/tmp/`).
- Anzisha programu ili kuepuka matatizo ya Gatekeeper na kuikadiria.

2. **Kufuta Faili ya NIB**:
- Badilisha faili ya NIB iliyopo (mfano, About Panel NIB) kwa faili ya DirtyNIB iliyoundwa.

3. **Utekelezaji**:
- Amsha utekelezaji kwa kuingiliana na programu (mfano, kuchagua kipengee cha menyu `About`).

#### Ushahidi wa Dhihirisho: Kupata Takwimu za Mtumiaji
- Badilisha AppleScript ili kufikia na kutoa takwimu za mtumiaji, kama picha, bila idhini ya mtumiaji.

### Mfano wa Msimbo: Faili ya .xib Mbaya
- Fikia na angalia [**mfano wa faili mbaya ya .xib**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4) inayodhihirisha kutekeleza msimbo usio na mipaka.

### Kukabiliana na Vikwazo vya Uzinduzi
- Vikwazo vya Uzinduzi vinakwamisha utekelezaji wa programu kutoka maeneo yasiyotarajiwa (mfano, `/tmp`).
- Inawezekana kubaini programu ambazo hazijalindwa na Vikwazo vya Uzinduzi na kuzilenga kwa uingizaji wa faili za NIB.

### Ulinzi wa ziada wa macOS
Kuanzia macOS Sonoma, mabadiliko ndani ya vifurushi vya Programu yamezuiliwa. Hata hivyo, mbinu za awali zilihusisha:
1. Nakala ya programu kwenye eneo tofauti (mfano, `/tmp/`).
2. Kubadilisha majina ya saraka ndani ya kifurushi cha programu ili kupita ulinzi wa awali.
3. Baada ya kuendesha programu ili kujiandikisha na Gatekeeper, kubadilisha kifurushi cha programu (mfano, kubadilisha MainMenu.nib na Dirty.nib).
4. Kubadilisha majina ya saraka nyuma na kuendesha tena programu ili kutekeleza faili ya NIB iliyounganishwa.

**Kumbuka**: Sasisho za hivi karibuni za macOS zimepunguza exploit hii kwa kuzuia mabadiliko ya faili ndani ya vifurushi vya programu baada ya caching ya Gatekeeper, na kufanya exploit hiyo isifanye kazi.


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
