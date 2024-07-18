# Виделка трюки

{% hint style="success" %}
Вивчайте та практикуйте хакінг AWS: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Навчання HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте хакінг GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Навчання HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримайте HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Поширюйте хакерські трюки, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв GitHub.

</details>
{% endhint %}

**Група з безпеки Try Hard**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## **Вилучення даних з файлів**

### **Binwalk**

Інструмент для пошуку вбудованих прихованих файлів та даних у бінарних файлах. Він встановлюється через `apt`, а його вихідний код доступний на [GitHub](https://github.com/ReFirmLabs/binwalk).
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Найголовніше**

Відновлює файли на основі їх заголовків та підписів, корисно для зображень у форматі png. Встановлюється через `apt` з джерелом на [GitHub](https://github.com/korczis/foremost).
```bash
foremost -i file # Extracts data
```
### **Exiftool**

Допомагає переглядати метадані файлу, доступний [тут](https://www.sno.phy.queensu.ca/\~phil/exiftool/).
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

Аналогічно до exiftool, для перегляду метаданих. Встановлюється через `apt`, джерело на [GitHub](https://github.com/Exiv2/exiv2), та має [офіційний веб-сайт](http://www.exiv2.org/).
```bash
exiv2 file # Shows the metadata
```
### **Файл**

Визначте тип файлу, з яким ви працюєте.

### **Рядки**

Витягає читабельні рядки з файлів, використовуючи різні налаштування кодування для фільтрації виводу.
```bash
strings -n 6 file # Extracts strings with a minimum length of 6
strings -n 6 file | head -n 20 # First 20 strings
strings -n 6 file | tail -n 20 # Last 20 strings
strings -e s -n 6 file # 7bit strings
strings -e S -n 6 file # 8bit strings
strings -e l -n 6 file # 16bit strings (little-endian)
strings -e b -n 6 file # 16bit strings (big-endian)
strings -e L -n 6 file # 32bit strings (little-endian)
strings -e B -n 6 file # 32bit strings (big-endian)
```
### **Порівняння (cmp)**

Корисно для порівняння модифікованого файлу з його оригінальною версією, знайденою в Інтернеті.
```bash
cmp original.jpg stego.jpg -b -l
```
## **Видобуток схованих даних в тексті**

### **Приховані дані в пробілах**

Невидимі символи в здається порожніх пробілах можуть приховувати інформацію. Щоб видобути ці дані, відвідайте [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).

## **Видобуток даних зображень**

### **Визначення деталей зображення за допомогою GraphicMagick**

[GraphicMagick](https://imagemagick.org/script/download.php) служить для визначення типів файлів зображень та виявлення потенційних пошкоджень. Виконайте наведену нижче команду, щоб перевірити зображення:
```bash
./magick identify -verbose stego.jpg
```
Щоб спробувати відновити пошкоджене зображення, може допомогти додавання коментаря до метаданих:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide для Приховування Даних**

Steghide сприяє приховуванню даних у файлах `JPEG, BMP, WAV та AU`, здатний вбудовувати та видобувати зашифровані дані. Встановлення просте за допомогою `apt`, а його [вихідний код доступний на GitHub](https://github.com/StefanoDeVuono/steghide).

**Команди:**

* `steghide info file` вказує, чи містить файл приховані дані.
* `steghide extract -sf file [--passphrase password]` видобуває приховані дані, пароль необов'язковий.

Для веб-основаного видобування відвідайте [цей веб-сайт](https://futureboy.us/stegano/decinput.html).

**Атака "Брутфорс" за допомогою Stegcracker:**

* Для спроби взлому пароля в Steghide використовуйте [stegcracker](https://github.com/Paradoxis/StegCracker.git) наступним чином:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg для файлів PNG та BMP**

zsteg спеціалізується на виявленні прихованих даних в файлах PNG та BMP. Встановлення виконується за допомогою `gem install zsteg`, з джерелом на [GitHub](https://github.com/zed-0xff/zsteg).

**Команди:**

* `zsteg -a file` застосовує всі методи виявлення до файлу.
* `zsteg -E file` вказує навантаження для вилучення даних.

### **StegoVeritas та Stegsolve**

**stegoVeritas** перевіряє метадані, виконує трансформації зображень та застосовує грубу силу LSB серед інших функцій. Використовуйте `stegoveritas.py -h` для повного списку параметрів та `stegoveritas.py stego.jpg` для виконання всіх перевірок.

**Stegsolve** застосовує різні кольорові фільтри для виявлення прихованих текстів або повідомлень в зображеннях. Він доступний на [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve).

### **FFT для виявлення прихованого вмісту**

Техніки швидкого перетворення Фур'є (FFT) можуть розкрити прихований вміст в зображеннях. Корисні ресурси включають:

* [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
* [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
* [FFTStegPic на GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy для аудіо- та зображення файлів**

Stegpy дозволяє вбудовувати інформацію в зображення та аудіофайли, підтримуючи формати, такі як PNG, BMP, GIF, WebP та WAV. Він доступний на [GitHub](https://github.com/dhsdshdhk/stegpy).

### **Pngcheck для аналізу файлів PNG**
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Додаткові Інструменти для Аналізу Зображень**

Для подальшого дослідження розгляньте відвідування:

* [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
* [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
* [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
* [OpenStego](https://www.openstego.com/)
* [DIIT](https://diit.sourceforge.net/)

## **Видобування Даних з Аудіофайлів**

**Аудіостеганографія** пропонує унікальний метод приховування інформації в звукових файлах. Для вбудовування або витягування прихованого вмісту використовуються різні інструменти.

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide є універсальним інструментом, призначеним для приховування даних в файлах JPEG, BMP, WAV та AU. Детальні інструкції наведені в [документації зі стеганографічними трюками](stego-tricks.md#steghide).

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

Цей інструмент сумісний з різноманітними форматами, включаючи PNG, BMP, GIF, WebP та WAV. Для отримання додаткової інформації звертайтеся до [розділу про Stegpy](stego-tricks.md#stegpy-png-bmp-gif-webp-wav).

### **ffmpeg**

ffmpeg є важливим для оцінки цілісності аудіофайлів, виділення детальної інформації та виявлення будь-яких розбіжностей.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavSteg відзначається у приховуванні та вилученні даних у WAV-файлах за допомогою стратегії менш значущого біта. Це доступно на [GitHub](https://github.com/ragibson/Steganography#WavSteg). Команди включають:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound дозволяє шифрування та виявлення інформації в звукових файлах за допомогою AES-256. Його можна завантажити з [офіційної сторінки](http://jpinsoft.net/deepsound/download.aspx).

### **Sonic Visualizer**

Незамінний інструмент для візуального та аналітичного інспектування аудіо файлів, Sonic Visualizer може розкрити приховані елементи, недоступні для виявлення іншими засобами. Відвідайте [офіційний веб-сайт](https://www.sonicvisualiser.org/) для отримання більше інформації.

### **DTMF Tones - Dial Tones**

Виявлення DTMF сигналів в аудіо файлах можливо завдяки онлайн інструментам, таким як [цей DTMF детектор](https://unframework.github.io/dtmf-detect/) та [DialABC](http://dialabc.com/sound/detect/index.html).

## **Інші Техніки**

### **Binary Length SQRT - QR Code**

Бінарні дані, які підносяться до квадратного кореня цілого числа, можуть представляти собою QR код. Використовуйте цей фрагмент коду для перевірки:
```python
import math
math.sqrt(2500) #50
```
### **Переклад Брайля**

Для перекладу Брайля використовуйте [Branah Braille Translator](https://www.branah.com/braille-translator) - це відмінний ресурс.

## **Посилання**

* [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
* [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)

**Група з безпеки Try Hard Security**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

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
