# macOS Defensive Apps

{% hint style="success" %}
AWS Hacking öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** bizi takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

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

* [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Her bir süreç tarafından yapılan her bağlantıyı izleyecektir. Moduna bağlı olarak (sessiz izin verilen bağlantılar, sessiz reddedilen bağlantılar ve uyarı) her yeni bağlantı kurulduğunda **size bir uyarı gösterecektir**. Ayrıca bu bilgileri görmek için çok güzel bir GUI'ye sahiptir.
* [**LuLu**](https://objective-see.org/products/lulu.html): Objective-See güvenlik duvarı. Bu, şüpheli bağlantılar için sizi uyaran temel bir güvenlik duvarıdır (bir GUI'si var ama Little Snitch'in GUI'si kadar şık değil).

## Persistence detection

* [**KnockKnock**](https://objective-see.org/products/knockknock.html): **Kötü amaçlı yazılımların kalıcı olabileceği** çeşitli yerlerde arama yapan Objective-See uygulaması (tek seferlik bir araç, izleme hizmeti değil).
* [**BlockBlock**](https://objective-see.org/products/blockblock.html): Kalıcılık oluşturan süreçleri izleyerek KnockKnock gibi çalışır.

## Keyloggers detection

* [**ReiKey**](https://objective-see.org/products/reikey.html): Klavye "olay tapları" kuran **keylogger'ları** bulmak için Objective-See uygulaması.
