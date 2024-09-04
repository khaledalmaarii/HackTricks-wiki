# macOS Memory Dumping

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


## Memory Artifacts

### Swap Files

Файли обміну, такі як `/private/var/vm/swapfile0`, слугують як **кеші, коли фізична пам'ять заповнена**. Коли в фізичній пам'яті більше немає місця, її дані передаються у файл обміну, а потім повертаються у фізичну пам'ять за потреби. Можуть бути присутніми кілька файлів обміну з іменами, такими як swapfile0, swapfile1 тощо.

### Hibernate Image

Файл, розташований за адресою `/private/var/vm/sleepimage`, є критично важливим під час **режиму гібернації**. **Дані з пам'яті зберігаються в цьому файлі, коли OS X переходить у гібернацію**. Після пробудження комп'ютера система отримує дані пам'яті з цього файлу, що дозволяє користувачу продовжити з того місця, де він зупинився.

Варто зазначити, що на сучасних системах MacOS цей файл зазвичай зашифрований з міркувань безпеки, що ускладнює відновлення.

* Щоб перевірити, чи увімкнено шифрування для sleepimage, можна виконати команду `sysctl vm.swapusage`. Це покаже, чи файл зашифрований.

### Memory Pressure Logs

Ще один важливий файл, пов'язаний з пам'яттю, у системах MacOS - це **журнал тиску пам'яті**. Ці журнали розташовані в `/var/log` і містять детальну інформацію про використання пам'яті системи та події тиску. Вони можуть бути особливо корисними для діагностики проблем, пов'язаних з пам'яттю, або для розуміння того, як система управляє пам'яттю з часом.

## Dumping memory with osxpmem

Щоб скинути пам'ять на машині MacOS, ви можете використовувати [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Note**: Наступні інструкції працюватимуть лише для Mac з архітектурою Intel. Цей інструмент зараз архівований, а останній реліз був у 2017 році. Бінарний файл, завантажений за допомогою наведених нижче інструкцій, націлений на чіпи Intel, оскільки Apple Silicon не існувала в 2017 році. Можливо, ви зможете скомпілювати бінарний файл для архітектури arm64, але вам доведеться спробувати самостійно.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Якщо ви знайдете цю помилку: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` Ви можете виправити це, виконавши:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Інші помилки** можуть бути виправлені **дозволивши завантаження kext** в "Безпека та конфіденційність --> Загальні", просто **дозвольте** це.

Ви також можете використовувати цей **однорядник** для завантаження програми, завантаження kext і дампу пам'яті:

{% code overflow="wrap" %}
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
{% endcode %}


{% hint style="success" %}
Вивчайте та практикуйте AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримайте HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Діліться хакерськими трюками, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на github.

</details>
{% endhint %}
