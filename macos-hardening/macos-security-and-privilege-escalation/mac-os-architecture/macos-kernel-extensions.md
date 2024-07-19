# macOS Kernel Extensions

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

## Basic Information

Kernel extensions (Kexts) ni **paket** zenye **`.kext`** upanuzi ambazo **zinapakiwa moja kwa moja kwenye nafasi ya kernel ya macOS**, zikitoa kazi za ziada kwa mfumo mkuu wa uendeshaji.

### Requirements

Kwa wazi, hii ni nguvu sana kwamba ni **ngumu kupakia upanuzi wa kernel**. Hizi ndizo **mahitaji** ambayo upanuzi wa kernel lazima ukidhi ili upakie:

* Wakati wa **kuingia kwenye hali ya urejeleaji**, **upanuzi wa kernel lazima ruhusiwe** kupakiwa:

<figure><img src="../../../.gitbook/assets/image (327).png" alt=""><figcaption></figcaption></figure>

* Upanuzi wa kernel lazima uwe **umetiwa saini na cheti cha saini ya msimbo wa kernel**, ambacho kinaweza tu **kupewa na Apple**. Nani atakayeangalia kwa undani kampuni na sababu zinazohitajika.
* Upanuzi wa kernel lazima pia uwe **umethibitishwa**, Apple itakuwa na uwezo wa kuangalia kwa malware.
* Kisha, mtumiaji wa **root** ndiye anayeweza **kupakia upanuzi wa kernel** na faili ndani ya pakiti lazima **zihusiane na root**.
* Wakati wa mchakato wa kupakia, pakiti lazima iwe tayari katika **mahali salama yasiyo ya root**: `/Library/StagedExtensions` (inahitaji ruhusa ya `com.apple.rootless.storage.KernelExtensionManagement`).
* Hatimaye, wakati wa kujaribu kuipakia, mtumiaji atapokea [**ombile la uthibitisho**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) na, ikiwa itakubaliwa, kompyuta lazima **irejeshwe** ili kuipakia.

### Loading process

Katika Catalina ilikuwa hivi: Ni muhimu kutaja kwamba mchakato wa **uthibitishaji** unafanyika katika **userland**. Hata hivyo, ni programu pekee zenye ruhusa ya **`com.apple.private.security.kext-management`** zinaweza **kuomba kernel kupakia upanuzi**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **inaanza** mchakato wa **uthibitishaji** wa kupakia upanuzi
* Itazungumza na **`kextd`** kwa kutuma kwa kutumia **Huduma ya Mach**.
2. **`kextd`** itakagua mambo kadhaa, kama vile **saini**
* Itazungumza na **`syspolicyd`** ili **kuangalia** ikiwa upanuzi unaweza **kupakiwa**.
3. **`syspolicyd`** itamwomba **mtumiaji** ikiwa upanuzi haujapakiwa hapo awali.
* **`syspolicyd`** itaripoti matokeo kwa **`kextd`**
4. **`kextd`** hatimaye itakuwa na uwezo wa **kueleza kernel kupakia** upanuzi

Ikiwa **`kextd`** haipatikani, **`kextutil`** inaweza kufanya ukaguzi sawa.

## Referencias

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

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
