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

## Podstawowe informacje

Rozszerzenia jądra (Kexts) to **pakiety** z rozszerzeniem **`.kext`**, które są **ładowane bezpośrednio do przestrzeni jądra macOS**, zapewniając dodatkową funkcjonalność głównemu systemowi operacyjnemu.

### Wymagania

Oczywiście, jest to tak potężne, że **załadowanie rozszerzenia jądra** jest **skomplikowane**. Oto **wymagania**, które musi spełniać rozszerzenie jądra, aby mogło być załadowane:

* Podczas **wejścia w tryb odzyskiwania**, rozszerzenia jądra **muszą być dozwolone** do załadowania:

<figure><img src="../../../.gitbook/assets/image (327).png" alt=""><figcaption></figcaption></figure>

* Rozszerzenie jądra musi być **podpisane certyfikatem podpisywania kodu jądra**, który może być **przyznany tylko przez Apple**. Kto dokładnie przeanalizuje firmę i powody, dla których jest to potrzebne.
* Rozszerzenie jądra musi być również **notaryzowane**, Apple będzie mogło sprawdzić je pod kątem złośliwego oprogramowania.
* Następnie, użytkownik **root** jest tym, który może **załadować rozszerzenie jądra**, a pliki wewnątrz pakietu muszą **należeć do roota**.
* Podczas procesu ładowania, pakiet musi być przygotowany w **chronionej lokalizacji nie-root**: `/Library/StagedExtensions` (wymaga przyznania `com.apple.rootless.storage.KernelExtensionManagement`).
* Na koniec, podczas próby załadowania, użytkownik [**otrzyma prośbę o potwierdzenie**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) i, jeśli zostanie zaakceptowana, komputer musi być **uruchomiony ponownie**, aby go załadować.

### Proces ładowania

W Catalina wyglądało to tak: Interesujące jest to, że proces **weryfikacji** zachodzi w **userland**. Jednak tylko aplikacje z przyznaniem **`com.apple.private.security.kext-management`** mogą **zażądać od jądra załadowania rozszerzenia**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **rozpoczyna** proces **weryfikacji** ładowania rozszerzenia
* Będzie komunikować się z **`kextd`**, wysyłając za pomocą **usługi Mach**.
2. **`kextd`** sprawdzi kilka rzeczy, takich jak **podpis**
* Będzie komunikować się z **`syspolicyd`**, aby **sprawdzić**, czy rozszerzenie może być **załadowane**.
3. **`syspolicyd`** **poprosi** **użytkownika**, jeśli rozszerzenie nie zostało wcześniej załadowane.
* **`syspolicyd`** przekaże wynik do **`kextd`**
4. **`kextd`** w końcu będzie mógł **powiedzieć jądru, aby załadowało** rozszerzenie

Jeśli **`kextd`** nie jest dostępny, **`kextutil`** może przeprowadzić te same kontrole.

## Referencje

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
