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

## Цілісність ПЗ

**Користувацьке ПЗ та/або скомпільовані двійкові файли можуть бути завантажені для використання вразливостей цілісності або перевірки підпису**. Наступні кроки можуть бути виконані для компіляції бекдору bind shell:

1. ПЗ може бути витягнуто за допомогою firmware-mod-kit (FMK).
2. Слід визначити архітектуру цільового ПЗ та порядок байтів.
3. Можна створити крос-компіллятор за допомогою Buildroot або інших відповідних методів для середовища.
4. Бекдор може бути створений за допомогою крос-компіллятора.
5. Бекдор може бути скопійований до витягнутого ПЗ в директорію /usr/bin.
6. Відповідний двійковий файл QEMU може бути скопійований до кореневої файлової системи витягнутого ПЗ.
7. Бекдор може бути емульований за допомогою chroot та QEMU.
8. До бекдору можна отримати доступ через netcat.
9. Двійковий файл QEMU слід видалити з кореневої файлової системи витягнутого ПЗ.
10. Модифіковане ПЗ може бути повторно упаковане за допомогою FMK.
11. Бекдоре ПЗ може бути протестовано шляхом емуляції його за допомогою інструментів аналізу ПЗ (FAT) та підключення до цільової IP-адреси та порту бекдору за допомогою netcat.

Якщо кореневий shell вже був отриманий через динамічний аналіз, маніпуляцію завантажувачем або тестування безпеки апаратного забезпечення, можуть бути виконані попередньо скомпільовані шкідливі двійкові файли, такі як імпланти або реверсні шелли. Автоматизовані інструменти для завантаження/імплантів, такі як фреймворк Metasploit та 'msfvenom', можуть бути використані за допомогою наступних кроків:

1. Слід визначити архітектуру цільового ПЗ та порядок байтів.
2. Msfvenom може бути використаний для вказівки цільового навантаження, IP-адреси хоста атакуючого, номера порту для прослуховування, типу файлу, архітектури, платформи та вихідного файлу.
3. Навантаження може бути передано на скомпрометований пристрій і забезпечено, щоб воно мало права на виконання.
4. Metasploit може бути підготовлений для обробки вхідних запитів, запустивши msfconsole та налаштувавши параметри відповідно до навантаження.
5. Реверсний шелл meterpreter може бути виконаний на скомпрометованому пристрої.
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
{% endhint %}
</details>
{% endhint %}
