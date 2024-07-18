# Локальне Хмарне Сховище

{% hint style="success" %}
Вивчайте та практикуйте AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримати HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Діліться хакерськими трюками, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на GitHub.

</details>
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Використовуйте [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=local-cloud-storage) для легкого створення та **автоматизації робочих процесів**, підтримуваних найсучаснішими інструментами спільноти.\
Отримайте доступ сьогодні:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=local-cloud-storage" %}

## OneDrive

У Windows ви можете знайти папку OneDrive за адресою `\Users\<username>\AppData\Local\Microsoft\OneDrive`. А всередині `logs\Personal` можна знайти файл `SyncDiagnostics.log`, який містить цікаві дані щодо синхронізованих файлів:

* Розмір у байтах
* Дата створення
* Дата модифікації
* Кількість файлів у хмарі
* Кількість файлів у папці
* **CID**: Унікальний ID користувача OneDrive
* Час генерації звіту
* Розмір жорсткого диска ОС

Після того, як ви знайдете CID, рекомендується **шукати файли, що містять цей ID**. Ви можете знайти файли з іменами: _**\<CID>.ini**_ та _**\<CID>.dat**_, які можуть містити цікаву інформацію, таку як назви файлів, синхронізованих з OneDrive.

## Google Drive

У Windows ви можете знайти основну папку Google Drive за адресою `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Ця папка містить файл під назвою Sync\_log.log з інформацією, такою як адреса електронної пошти облікового запису, імена файлів, мітки часу, MD5 хеші файлів тощо. Навіть видалені файли з'являються в цьому файлі журналу з відповідним MD5.

Файл **`Cloud_graph\Cloud_graph.db`** є базою даних sqlite, яка містить таблицю **`cloud_graph_entry`**. У цій таблиці ви можете знайти **назви** **синхронізованих** **файлів**, час модифікації, розмір та MD5 контрольну суму файлів.

Дані таблиці бази даних **`Sync_config.db`** містять адресу електронної пошти облікового запису, шлях до спільних папок та версію Google Drive.

## Dropbox

Dropbox використовує **SQLite бази даних** для управління файлами. У цьому\
Ви можете знайти бази даних у папках:

* `\Users\<username>\AppData\Local\Dropbox`
* `\Users\<username>\AppData\Local\Dropbox\Instance1`
* `\Users\<username>\AppData\Roaming\Dropbox`

А основні бази даних:

* Sigstore.dbx
* Filecache.dbx
* Deleted.dbx
* Config.dbx

Розширення ".dbx" означає, що **бази даних** є **зашифрованими**. Dropbox використовує **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/previous-versions/ms995355\(v=msdn.10\)?redirectedfrom=MSDN))

Щоб краще зрозуміти шифрування, яке використовує Dropbox, ви можете прочитати [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).

Однак основна інформація:

* **Ентропія**: d114a55212655f74bd772e37e64aee9b
* **Сіль**: 0D638C092E8B82FC452883F95F355B8E
* **Алгоритм**: PBKDF2
* **Ітерації**: 1066

Окрім цієї інформації, для розшифрування баз даних вам також знадобиться:

* **Зашифрований ключ DPAPI**: Ви можете знайти його в реєстрі за адресою `NTUSER.DAT\Software\Dropbox\ks\client` (експортуйте ці дані у бінарному вигляді)
* **`SYSTEM`** та **`SECURITY`** хіви
* **Головні ключі DPAPI**: які можна знайти за адресою `\Users\<username>\AppData\Roaming\Microsoft\Protect`
* **Ім'я користувача** та **пароль** користувача Windows

Тоді ви можете використовувати інструмент [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi\_data\_decryptor.html)**:**

![](<../../../.gitbook/assets/image (443).png>)

Якщо все піде за планом, інструмент вкаже на **основний ключ**, який вам потрібно **використати для відновлення оригінального**. Щоб відновити оригінал, просто використовуйте цей [рецепт cyber\_chef](https://gchq.github.io/CyberChef/#recipe=Derive\_PBKDF2\_key\(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D\)), ставлячи основний ключ як "пароль" у рецепті.

Отриманий hex є фінальним ключем, використаним для шифрування баз даних, які можна розшифрувати за допомогою:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
The **`config.dbx`** база даних містить:

* **Email**: Електронна пошта користувача
* **usernamedisplayname**: Ім'я користувача
* **dropbox\_path**: Шлях, де знаходиться папка dropbox
* **Host\_id: Hash** використовується для аутентифікації в хмарі. Це можна скасувати лише з вебу.
* **Root\_ns**: Ідентифікатор користувача

The **`filecache.db`** база даних містить інформацію про всі файли та папки, синхронізовані з Dropbox. Таблиця `File_journal` є тією, що містить більше корисної інформації:

* **Server\_path**: Шлях, де файл знаходиться на сервері (цей шлях передує `host_id` клієнта).
* **local\_sjid**: Версія файлу
* **local\_mtime**: Дата модифікації
* **local\_ctime**: Дата створення

Інші таблиці всередині цієї бази даних містять більш цікаву інформацію:

* **block\_cache**: хеш усіх файлів та папок Dropbox
* **block\_ref**: Пов'язує хеш ID таблиці `block_cache` з ID файлу в таблиці `file_journal`
* **mount\_table**: Спільні папки Dropbox
* **deleted\_fields**: Видалені файли Dropbox
* **date\_added**

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Використовуйте [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=local-cloud-storage) для легкого створення та **автоматизації робочих процесів**, підтримуваних **найсучаснішими** інструментами спільноти.\
Отримайте доступ сьогодні:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=local-cloud-storage" %}

{% hint style="success" %}
Вчіться та практикуйте AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вчіться та практикуйте GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримати HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Діліться хакерськими трюками, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на github.

</details>
{% endhint %}
