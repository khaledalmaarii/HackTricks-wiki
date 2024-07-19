# macOS Defensive Apps

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
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## Firewalls

* [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Będzie monitorować każde połączenie nawiązane przez każdy proces. W zależności od trybu (ciche zezwolenie na połączenia, ciche odrzucenie połączenia i powiadomienie) **pokaże ci powiadomienie** za każdym razem, gdy nawiązywane jest nowe połączenie. Posiada również bardzo ładny interfejs graficzny do przeglądania tych informacji.
* [**LuLu**](https://objective-see.org/products/lulu.html): Zapora sieciowa Objective-See. To podstawowa zapora, która powiadomi cię o podejrzanych połączeniach (ma interfejs graficzny, ale nie jest tak elegancki jak ten w Little Snitch).

## Persistence detection

* [**KnockKnock**](https://objective-see.org/products/knockknock.html): Aplikacja Objective-See, która przeszuka kilka lokalizacji, gdzie **złośliwe oprogramowanie może się utrzymywać** (to narzędzie jednorazowe, a nie usługa monitorująca).
* [**BlockBlock**](https://objective-see.org/products/blockblock.html): Podobnie jak KnockKnock, monitorując procesy, które generują utrzymywanie.

## Keyloggers detection

* [**ReiKey**](https://objective-see.org/products/reikey.html): Aplikacja Objective-See do znajdowania **keyloggerów**, które instalują "event taps" na klawiaturze.
