# FISSURE - Радіочастотний фреймворк

**Незалежне від частоти розуміння сигналу на основі SDR та зворотне проектування**

FISSURE - це відкритий радіочастотний та фреймворк зворотного проектування, призначений для всіх рівнів навичок з гачками для виявлення та класифікації сигналів, виявлення протоколів, виконання атак, маніпулювання IQ, аналізу вразливостей, автоматизації та штучного інтелекту/машинного навчання. Фреймворк був створений для прискорення інтеграції програмних модулів, радіо, протоколів, даних сигналів, скриптів, потокових графіків, довідкового матеріалу та інструментів сторонніх розробників. FISSURE є засобом для організації робочих процесів, який дозволяє зберігати програмне забезпечення в одному місці та дозволяє командам легко орієнтуватися, ділитися тим самим перевіреним базовим конфігураційним файлом для конкретних дистрибутивів Linux.

Фреймворк та інструменти, що постачаються з FISSURE, призначені для виявлення наявності радіочастотної енергії, розуміння характеристик сигналу, збору та аналізу вибірок, розробки технік передачі та/або ін'єкції, а також створення власних навантажень або повідомлень. FISSURE містить зростаючу бібліотеку інформації про протоколи та сигнали для допомоги в ідентифікації, створенні пакетів та тестуванні. Існують можливості онлайн-архіву для завантаження файлів сигналів та створення плейлистів для моделювання трафіку та тестування систем.

Дружній код Python та користувацький інтерфейс дозволяють початківцям швидко вивчити популярні інструменти та техніки, пов'язані з радіочастотними технологіями та зворотнім проектуванням. Викладачі в галузі кібербезпеки та інженерії можуть скористатися вбудованим матеріалом або використовувати фреймворк для демонстрації власних застосувань у реальному світі. Розробники та дослідники можуть використовувати FISSURE для щоденних завдань або для викладення своїх передових рішень широкій аудиторії. Зі зростанням усвідомленості та використання FISSURE в спільноті зростатиме і обсяг його можливостей, і широта технологій, які він охоплює.

**Додаткова інформація**

* [Сторінка AIS](https://www.ainfosec.com/technologies/fissure/)
* [Слайди GRCon22](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [Стаття GRCon22](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [Відео GRCon22](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Транскрипт чату Hack](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Початок роботи

**Підтримується**

У FISSURE є три гілки, щоб полегшити навігацію по файлам та зменшити зайвість коду. Гілка Python2\_maint-3.7 містить кодову базу, побудовану навколо Python2, PyQt4 та GNU Radio 3.7; гілка Python3\_maint-3.8 побудована навколо Python3, PyQt5 та GNU Radio 3.8; а гілка Python3\_maint-3.10 побудована навколо Python3, PyQt5 та GNU Radio 3.10.

| Операційна система | Гілка FISSURE |
| :------------------: | :----------------: |
|  Ubuntu 18.04 (x64)  | Python2\_maint-3.7 |
| Ubuntu 18.04.5 (x64) | Python2\_maint-3.7 |
| Ubuntu 18.04.6 (x64) | Python2\_maint-3.7 |
| Ubuntu 20.04.1 (x64) | Python3\_maint-3.8 |
| Ubuntu 20.04.4 (x64) | Python3\_maint-3.8 |
|  KDE neon 5.25 (x64) | Python3\_maint-3.8 |

**У процесі (бета-версія)**

Ці операційні системи все ще перебувають у статусі бета-версії. Вони знаходяться в стадії розробки, і відомо, що відсутні деякі функції. Елементи встановлювача можуть конфліктувати з існуючими програмами або не встановлюватися до тих пір, поки статус не буде знятий.

| Операційна система | Гілка FISSURE |
| :----------------------: | :-----------------: |
| DragonOS Focal (x86\_64) |  Python3\_maint-3.8 |
|    Ubuntu 22.04 (x64)    | Python3\_maint-3.10 |

Примітка: Деякі програмні інструменти не працюють для кожної ОС. Див. [Програмне забезпечення та конфлікти](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md)

**Встановлення**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
Це встановить залежності програмного забезпечення PyQt, необхідні для запуску інтерфейсів установки, якщо вони не знайдені.

Далі виберіть опцію, яка найкраще відповідає вашій операційній системі (має бути автоматично виявлена, якщо ваша ОС відповідає опції).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Рекомендується встановлювати FISSURE на чисту операційну систему, щоб уникнути конфліктів. Виберіть всі рекомендовані прапорці (кнопка за замовчуванням), щоб уникнути помилок під час роботи з різними інструментами у FISSURE. Під час установки буде кілька запитів, переважно щодо підвищених дозволів та імен користувачів. Якщо елемент містить розділ "Verify" в кінці, встановлювач виконає команду, яка йде після і підсвітить прапорець зеленим або червоним, залежно від того, чи виникли помилки під час виконання команди. Позначені елементи без розділу "Verify" залишаться чорними після встановлення.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Використання**

Відкрийте термінал та введіть:
```
fissure
```
## Деталі

**Компоненти**

* Інформаційна панель
* Центральний хаб (HIPRFISR)
* Ідентифікація цільового сигналу (TSI)
* Відкриття протоколу (PD)
* Граф потоку та виконавець скриптів (FGE)

![компоненти](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Можливості**

| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Детектор сигналу**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**Маніпулювання IQ**_      | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Пошук сигналу**_          | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Розпізнавання шаблону**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Атаки**_           | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Плейлисти сигналів**_       | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Галерея зображень**_  |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Створення пакетів**_   | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Інтеграція Scapy**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**Калькулятор CRC**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Журналювання**_            |

**Обладнання**

Нижче наведений список "підтримуваного" обладнання з різними рівнями інтеграції:

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx
* HackRF
* RTL2832U
* 802.11 адаптери
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR

## Уроки

FISSURE поставляється з кількома корисними посібниками для ознайомлення з різними технологіями та методиками. Багато з них включають кроки з використання різних інструментів, які інтегровані в FISSURE.

* [Урок1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Урок2: Розбір Lua](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Урок3: Обмін звуком](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Урок4: Плати ESP](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Урок5: Відстеження радіозондів](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Урок6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Урок7: Типи даних](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Урок8: Власні блоки GNU Radio](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Урок9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Урок10: Екзамени радіоаматорів](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Урок11: Інструменти Wi-Fi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)

## План

* [ ] Додати більше типів обладнання, RF протоколів, параметрів сигналу, інструментів аналізу
* [ ] Підтримка більшої кількості операційних систем
* [ ] Розробка навчального матеріалу щодо FISSURE (RF атаки, Wi-Fi, GNU Radio, PyQt тощо)
* [ ] Створення засобу умовного сигналу, екстрактора функцій та класифікатора сигналу з вибором технік штучного інтелекту/машинного навчання
* [ ] Реалізація рекурсивних механізмів демодуляції для отримання послідовності бітів з невідомих сигналів
* [ ] Перехід основних компонентів FISSURE до загальної схеми розгортання датчиків

## Співпраця

Запрошуються пропозиції щодо поліпшення FISSURE. Залиште коментар на сторінці [Обговорення](https://github.com/ainfosec/FISSURE/discussions) або в Discord-сервері, якщо у вас є думки щодо наступного:

* Нові пропозиції щодо функціоналу та змін дизайну
* Програмні інструменти з кроками встановлення
* Нові уроки або додатковий матеріал для існуючих уроків
* RF протоколи, які цікавлять
* Більше типів обладнання та типів SDR для інтеграції
* Скрипти аналізу IQ на Python
* Виправлення та поліпшення встановлення

Внесок у поліпшення FISSURE є важливим для прискорення його розвитку. Будь-які ваші внески вельми цінні. Якщо ви бажаєте внести внесок через розробку коду, будь ласка, зробіть так:

1. Склонуйте проект
2. Створіть свою функціональну гілку (`git checkout -b feature/AmazingFeature`)
3. Зробіть коміт ваших змін (`git commit -m 'Add some AmazingFeature'`)
4. Запуште гілку (`git push origin feature/AmazingFeature`)
5. Відкрийте запит на витяг

Створення [Проблем](https://github.com/ainfosec/FISSURE/issues), щоб привернути увагу до помилок, також вітається.

## Співпраця

Звертайтеся до розвитку бізнесу Assured Information Security, Inc. (AIS), щоб запропонувати та узаконити будь-які можливості співпраці з FISSURE – чи то через відділення часу на інтеграцію вашого програмного забезпечення, чи через розробку рішень для ваших технічних викликів талановитими фахівцями AIS, чи через інтеграцію FISSURE в інші платформи/додатки.

## Ліцензія

GPL-3.0

Для деталей ліцензії дивіться файл LICENSE.
## Контакт

Приєднуйтесь до сервера Discord: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Слідкуйте в Twitter: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Кріс Пур - Assured Information Security, Inc. - poorec@ainfosec.com

Розвиток бізнесу - Assured Information Security, Inc. - bd@ainfosec.com

## Кредити

Ми визнаємо та вдячні цим розробникам:

[Credits](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Подяки

Особлива подяка доктору Самуелю Мантраваді та Джозефу Рейту за їх внесок у цей проект.
