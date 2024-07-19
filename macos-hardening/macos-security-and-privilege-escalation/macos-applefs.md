# macOS AppleFS

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

## Apple Приватна Файлова Система (APFS)

**Apple File System (APFS)** - це сучасна файлова система, розроблена для заміни ієрархічної файлової системи Plus (HFS+). Її розробка була зумовлена потребою в **покращеній продуктивності, безпеці та ефективності**.

Деякі помітні особливості APFS включають:

1. **Спільне використання простору**: APFS дозволяє кільком томам **ділити один і той же вільний простір** на одному фізичному пристрої. Це забезпечує більш ефективне використання простору, оскільки томи можуть динамічно зростати і зменшуватися без необхідності ручного зміни розміру або перерозподілу.
1. Це означає, що в порівнянні з традиційними розділами на файлових дисках, **в APFS різні розділи (томи) ділять весь дисковий простір**, тоді як звичайний розділ зазвичай мав фіксований розмір.
2. **Снапшоти**: APFS підтримує **створення снапшотів**, які є **тільки для читання**, точковими моментами часу файлової системи. Снапшоти дозволяють ефективні резервні копії та легкі відкат системи, оскільки вони споживають мінімум додаткового простору для зберігання і можуть бути швидко створені або скасовані.
3. **Клони**: APFS може **створювати клони файлів або каталогів, які ділять той же простір для зберігання** з оригіналом, поки або клон, або оригінальний файл не буде змінено. Ця функція забезпечує ефективний спосіб створення копій файлів або каталогів без дублювання простору для зберігання.
4. **Шифрування**: APFS **нативно підтримує шифрування всього диска**, а також шифрування на рівні файлів і каталогів, підвищуючи безпеку даних у різних випадках використання.
5. **Захист від збоїв**: APFS використовує **схему метаданих копіювання при запису, яка забезпечує узгодженість файлової системи** навіть у випадках раптової втрати живлення або збоїв системи, зменшуючи ризик пошкодження даних.

В цілому, APFS пропонує більш сучасну, гнучку та ефективну файлову систему для пристроїв Apple, з акцентом на покращену продуктивність, надійність і безпеку.
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

Том `Data` змонтовано в **`/System/Volumes/Data`** (ви можете перевірити це за допомогою `diskutil apfs list`).

Список firmlinks можна знайти у файлі **`/usr/share/firmlinks`**.
```bash
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
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

{% endhint %}
</details>
{% endhint %}
