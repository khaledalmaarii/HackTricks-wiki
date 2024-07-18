# Wifi Pcap Analysis

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

## Check BSSIDs

Коли ви отримуєте захоплення, основний трафік якого - Wifi, використовуючи WireShark, ви можете почати досліджувати всі SSID захоплення з _Wireless --> WLAN Traffic_:

![](<../../../.gitbook/assets/image (106).png>)

![](<../../../.gitbook/assets/image (492).png>)

### Brute Force

Одна з колонок цього екрану вказує, чи **була знайдена будь-яка аутентифікація всередині pcap**. Якщо це так, ви можете спробувати зламати її за допомогою `aircrack-ng`:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Наприклад, він отримає WPA пароль, що захищає PSK (попередньо поділений ключ), який буде потрібен для розшифровки трафіку пізніше.

## Дані в Beacon'ах / Бічний канал

Якщо ви підозрюєте, що **дані витікають у beacon'ах Wifi мережі**, ви можете перевірити beacon'и мережі, використовуючи фільтр, подібний до наступного: `wlan contains <NAMEofNETWORK>`, або `wlan.ssid == "NAMEofNETWORK"` шукайте в відфільтрованих пакетах підозрілі рядки.

## Знайти невідомі MAC-адреси в Wifi мережі

Наступне посилання буде корисним для знаходження **машин, що надсилають дані в Wifi мережі**:

* `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Якщо ви вже знаєте **MAC-адреси, ви можете видалити їх з виходу**, додавши перевірки, подібні до цієї: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Якщо ви виявили **невідомі MAC** адреси, що спілкуються в мережі, ви можете використовувати **фільтри**, подібні до наступного: `wlan.addr==<MAC address> && (ftp || http || ssh || telnet)`, щоб відфільтрувати їх трафік. Зверніть увагу, що фільтри ftp/http/ssh/telnet корисні, якщо ви розшифрували трафік.

## Розшифрувати трафік

Edit --> Preferences --> Protocols --> IEEE 802.11--> Edit

![](<../../../.gitbook/assets/image (499).png>)

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
