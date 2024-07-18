# Форензика Docker

{% hint style="success" %}
Вивчайте та практикуйте взлом AWS: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Навчання HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте взлом GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Навчання HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримайте HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Поширюйте хакерські трюки, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на GitHub.

</details>
{% endhint %}

## Зміна контейнера

Є підозри, що деякий контейнер Docker був скомпрометований:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Ви легко можете **знайти модифікації, внесені до цього контейнера щодо зображення**, за допомогою:
```bash
docker diff wordpress
C /var
C /var/lib
C /var/lib/mysql
A /var/lib/mysql/ib_logfile0
A /var/lib/mysql/ib_logfile1
A /var/lib/mysql/ibdata1
A /var/lib/mysql/mysql
A /var/lib/mysql/mysql/time_zone_leap_second.MYI
A /var/lib/mysql/mysql/general_log.CSV
...
```
У попередній команді **C** означає **Змінено**, а **A,** **Додано**. Якщо ви виявите, що який-небудь цікавий файл, наприклад `/etc/shadow`, був змінений, ви можете завантажити його з контейнера, щоб перевірити наявність зловмисної діяльності за допомогою:
```bash
docker cp wordpress:/etc/shadow.
```
Ви також можете **порівняти його з оригіналом**, запустивши новий контейнер і витягнувши файл з нього:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Якщо ви виявите, що **додано підозрілий файл**, ви можете отримати доступ до контейнера та перевірити його:
```bash
docker exec -it wordpress bash
```
## Зміни в зображеннях

Коли вам надають експортоване зображення Docker (найімовірніше у форматі `.tar`), ви можете використовувати [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases), щоб **витягти підсумок змін**:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Після цього ви можете **розпакувати** зображення та **отримати доступ до кульок**, щоб шукати підозрілі файли, які ви могли знайти в історії змін:
```bash
tar -xf image.tar
```
### Базовий аналіз

Ви можете отримати **базову інформацію** з образу, що працює:
```bash
docker inspect <image>
```
Ви також можете отримати **історію змін** за допомогою:
```bash
docker history --no-trunc <image>
```
Ви також можете створити **dockerfile з образу** за допомогою:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Занурення

Для пошуку доданих/змінених файлів в образах Docker ви також можете використовувати [**dive**](https://github.com/wagoodman/dive) (завантажте його з [**релізів**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)):
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Це дозволяє вам **переміщатися між різними блоками образів Docker** та перевіряти, які файли були змінені/додані. **Червоний** означає додано, а **жовтий** - змінено. Використовуйте **Tab**, щоб перейти до іншого виду, та **Пробіл**, щоб згорнути/розгорнути папки.

За допомогою die ви не зможете отримати доступ до вмісту різних етапів зображення. Для цього вам потрібно **розпакувати кожен шар та отримати до нього доступ**.\
Ви можете розпакувати всі шари зображення з каталогу, де було розпаковано зображення, виконавши:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Облікові дані з пам'яті

Зверніть увагу, що коли ви запускаєте контейнер Docker всередині хоста **ви можете бачити процеси, що працюють в контейнері з хоста**, просто запустивши `ps -ef`

Отже (як root) ви можете **вивантажити пам'ять процесів** з хоста та шукати **облікові дані** просто [**як у наступному прикладі**](../../linux-hardening/privilege-escalation/#process-memory).
