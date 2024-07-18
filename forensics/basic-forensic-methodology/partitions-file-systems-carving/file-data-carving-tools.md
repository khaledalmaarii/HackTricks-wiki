{% hint style="success" %}
Вивчайте та вправляйтесь в хакінгу AWS: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Навчання AWS Red Team Expert (ARTE) від HackTricks**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та вправляйтесь в хакінгу GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Навчання GCP Red Team Expert (GRTE) від HackTricks**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримайте HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Поширюйте хакерські трюки, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на GitHub.

</details>
{% endhint %}


# Інструменти для відновлення даних

## Autopsy

Найпоширеніший інструмент, який використовується в судовому розшуку для вилучення файлів з образів - це [**Autopsy**](https://www.autopsy.com/download/). Завантажте його, встановіть та використовуйте для пошуку "прихованих" файлів у файлі. Зверніть увагу, що Autopsy призначений для роботи з образами дисків та іншого роду образами, а не просто файлами.

## Binwalk <a id="binwalk"></a>

**Binwalk** - це інструмент для пошуку вбудованих файлів та даних у бінарних файлах, таких як зображення та аудіофайли.
Він може бути встановлений за допомогою `apt`, однак [вихідний код](https://github.com/ReFirmLabs/binwalk) можна знайти на GitHub.
**Корисні команди**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

Ще один поширений інструмент для пошуку прихованих файлів - **foremost**. Ви можете знайти файл конфігурації foremost у `/etc/foremost.conf`. Якщо ви хочете лише знайти певні файли, розкоментуйте їх. Якщо ви нічого не розкоментуєте, foremost буде шукати файли, налаштовані за замовчуванням.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Scalpel**

**Scalpel** - це ще один інструмент, який можна використовувати для пошуку та вилучення **файлів, вбудованих у файл**. У цьому випадку вам потрібно розкоментувати типи файлів, які ви хочете видобути з конфігураційного файлу \(_/etc/scalpel/scalpel.conf_\).
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

Цей інструмент входить до складу Kali, але ви можете знайти його тут: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk_extractor)

Цей інструмент може сканувати зображення та **видобувати pcaps** всередині нього, **мережеву інформацію \(URL-адреси, домени, IP-адреси, MAC-адреси, пошту\)** та інші **файли**. Вам потрібно лише виконати:
```text
bulk_extractor memory.img -o out_folder
```
Пройдіть через **всю інформацію**, яку зібрав інструмент \(паролі?\), **проаналізуйте** **пакети** \(читайте [**аналіз Pcaps**](../pcap-inspection/)\), шукайте **дивні домени** \(домени, пов'язані з **шкідливим ПЗ** або **несущісніми**\).

## PhotoRec

Ви можете знайти його за посиланням [https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)

Він постачається з версією GUI та CLI. Ви можете вибрати **типи файлів**, які ви хочете, щоб PhotoRec їх шукав.

![](../../../.gitbook/assets/image%20%28524%29.png)

# Конкретні інструменти для відновлення даних

## FindAES

Шукає ключі AES, шукаючи їх розклади ключів. Здатний знаходити ключі 128, 192 та 256 біт, такі, як ті, що використовуються TrueCrypt та BitLocker.

Завантажте [тут](https://sourceforge.net/projects/findaes/).

# Допоміжні інструменти

Ви можете використовувати [**viu** ](https://github.com/atanunq/viu), щоб переглядати зображення з терміналу.
Ви можете використовувати інструмент командного рядка linux **pdftotext**, щоб перетворити pdf у текст і прочитати його.



{% hint style="success" %}
Вивчайте та практикуйте взлом AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Навчання HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте взлом GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Навчання HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримайте HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Поширюйте хакерські трюки, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на GitHub.

</details>
{% endhint %}
