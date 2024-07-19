# macOS Apple Scripts

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

## Apple Scripts

Bu, **uzaktan süreçlerle etkileşimde bulunan** görev otomasyonu için kullanılan bir betik dilidir. **Diğer süreçlerden bazı eylemleri gerçekleştirmesini istemek** oldukça kolay hale getirir. **Kötü amaçlı yazılımlar**, bu özellikleri kullanarak diğer süreçler tarafından dışa aktarılan işlevleri kötüye kullanabilir.\
Örneğin, bir kötü amaçlı yazılım **tarayıcıda açılan sayfalara rastgele JS kodu enjekte edebilir**. Veya **kullanıcıdan istenen bazı izinleri otomatik olarak tıklayabilir**;
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Burada bazı örnekler var: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Kötü amaçlı yazılımlar hakkında daha fazla bilgi için [**buradan**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/) ulaşabilirsiniz.

Apple script'leri kolayca "**derlenebilir**". Bu sürümler `osadecompile` ile kolayca "**açılabilir**".

Ancak, bu script'ler **"Sadece okunur"** olarak da **dışa aktarılabilir** ( "Dışa Aktar..." seçeneği aracılığıyla):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/.gitbook/assets/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
ve bu durumda içerik `osadecompile` ile bile decompile edilemez

Ancak, bu tür yürütülebilir dosyaları anlamak için kullanılabilecek bazı araçlar hala mevcuttur, [**daha fazla bilgi için bu araştırmayı okuyun**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) aracı ve [**aevt\_decompile**](https://github.com/SentineLabs/aevt\_decompile) aracı, scriptin nasıl çalıştığını anlamak için çok faydalı olacaktır.

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
