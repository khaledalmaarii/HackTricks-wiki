# Weaponizing Distroless

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

## Co to jest Distroless

Kontener distroless to rodzaj kontenera, który **zawiera tylko niezbędne zależności do uruchomienia konkretnej aplikacji**, bez dodatkowego oprogramowania lub narzędzi, które nie są wymagane. Te kontenery są zaprojektowane, aby być jak **najlżejsze** i **najbezpieczniejsze** jak to możliwe, a ich celem jest **minimalizacja powierzchni ataku** poprzez usunięcie wszelkich zbędnych komponentów.

Kontenery distroless są często używane w **środowiskach produkcyjnych, gdzie bezpieczeństwo i niezawodność są kluczowe**.

Niektóre **przykłady** **kontenerów distroless** to:

* Dostarczone przez **Google**: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
* Dostarczone przez **Chainguard**: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Weaponizing Distroless

Celem uzbrojenia kontenera distroless jest możliwość **wykonywania dowolnych binarek i ładunków, nawet z ograniczeniami** narzuconymi przez **distroless** (brak powszechnych binarek w systemie) oraz ochronami powszechnie spotykanymi w kontenerach, takimi jak **tylko do odczytu** lub **brak wykonania** w `/dev/shm`.

### Przez pamięć

Nadchodzi w pewnym momencie 2023...

### Poprzez istniejące binarki

#### openssl

****[**W tym poście,**](https://www.form3.tech/engineering/content/exploiting-distroless-images) wyjaśniono, że binarka **`openssl`** jest często znajdowana w tych kontenerach, potencjalnie dlatego, że jest **potrzebna** przez oprogramowanie, które ma działać wewnątrz kontenera.


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
