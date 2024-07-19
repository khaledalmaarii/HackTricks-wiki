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

To język skryptowy używany do automatyzacji zadań **interakcji z procesami zdalnymi**. Umożliwia łatwe **proszę inne procesy o wykonanie pewnych działań**. **Złośliwe oprogramowanie** może nadużywać tych funkcji, aby wykorzystywać funkcje eksportowane przez inne procesy.\
Na przykład, złośliwe oprogramowanie mogłoby **wstrzykiwać dowolny kod JS w otwartych stronach przeglądarki**. Lub **automatycznie klikać** niektóre pozwolenia wymagane od użytkownika;
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Here you have some examples: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Find more info about malware using applescripts [**here**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

Apple scripts mogą być łatwo "**kompilowane**". Te wersje mogą być łatwo "**dekompilowane**" za pomocą `osadecompile`

Jednak te skrypty mogą być również **eksportowane jako "Tylko do odczytu"** (poprzez opcję "Eksportuj..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/.gitbook/assets/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
i w tym przypadku zawartość nie może być dekompilowana nawet za pomocą `osadecompile`

Jednak nadal istnieją narzędzia, które można wykorzystać do zrozumienia tego rodzaju plików wykonywalnych, [**przeczytaj to badanie, aby uzyskać więcej informacji**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). Narzędzie [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) z [**aevt\_decompile**](https://github.com/SentineLabs/aevt\_decompile) będzie bardzo przydatne do zrozumienia, jak działa skrypt.

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
