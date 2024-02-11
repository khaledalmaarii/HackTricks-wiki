# Bezpieczeństwo Docker

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo tworzyć i **automatyzować przepływy pracy** przy użyciu najbardziej zaawansowanych narzędzi społecznościowych na świecie.\
Otrzymaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## **Podstawowe zabezpieczenia silnika Docker**

Silnik Docker wykorzystuje **Namespaces** i **Cgroups** jądra Linuxa do izolacji kontenerów, oferując podstawową warstwę zabezpieczeń. Dodatkową ochronę zapewnia **Capabilities dropping**, **Seccomp** i **SELinux/AppArmor**, zwiększając izolację kontenerów. Plugin **auth** może dodatkowo ograniczać działania użytkownika.

![Bezpieczeństwo Docker](https://sreeninet.files.wordpress.com/2016/03/dockersec1.png)

### Bezpieczny dostęp do silnika Docker

Silnik Docker można uzyskać zarówno lokalnie za pomocą gniazda Unix, jak i zdalnie za pomocą protokołu HTTP. W przypadku zdalnego dostępu ważne jest korzystanie z HTTPS i **TLS**, aby zapewnić poufność, integralność i uwierzytelnianie.

Domyślnie silnik Docker nasłuchuje na gnieździe Unix pod adresem `unix:///var/run/docker.sock`. W systemach Ubuntu opcje uruchamiania Dockera są definiowane w pliku `/etc/default/docker`. Aby umożliwić zdalny dostęp do interfejsu API i klienta Dockera, należy udostępnić demona Dockera za pomocą gniazda HTTP, dodając następujące ustawienia:
```bash
DOCKER_OPTS="-D -H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Jednakże, nie zaleca się wystawiania demona Docker przez HTTP ze względów bezpieczeństwa. Zaleca się zabezpieczenie połączeń za pomocą protokołu HTTPS. Istnieją dwie główne metody zabezpieczania połączenia:
1. Klient weryfikuje tożsamość serwera.
2. Zarówno klient, jak i serwer wzajemnie uwierzytelniają swoją tożsamość.

Do potwierdzenia tożsamości serwera wykorzystuje się certyfikaty. Szczegółowe przykłady obu metod można znaleźć w [**tym przewodniku**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/).

### Bezpieczeństwo obrazów kontenerów

Obrazy kontenerów mogą być przechowywane w prywatnych lub publicznych repozytoriach. Docker oferuje kilka opcji przechowywania obrazów kontenerów:

* **[Docker Hub](https://hub.docker.com)**: Publiczna usługa rejestru od Docker.
* **[Docker Registry](https://github.com/docker/distribution)**: Projekt open-source, który umożliwia użytkownikom hostowanie własnego rejestru.
* **[Docker Trusted Registry](https://www.docker.com/docker-trusted-registry)**: Komercyjna oferta rejestru od Docker, oferująca uwierzytelnianie użytkowników oparte na rolach oraz integrację z usługami katalogowymi LDAP.

### Skanowanie obrazów

Kontenery mogą mieć **luki w zabezpieczeniach** zarówno ze względu na obraz bazowy, jak i oprogramowanie zainstalowane na nim. Docker pracuje nad projektem o nazwie **Nautilus**, który skanuje kontenery pod kątem bezpieczeństwa i wylicza podatności. Nautilus działa poprzez porównanie każdej warstwy obrazu kontenera z repozytorium podatności w celu identyfikacji luk w zabezpieczeniach.

Aby uzyskać więcej [**informacji, przeczytaj to**](https://docs.docker.com/engine/scan/).

* **`docker scan`**

Polecenie **`docker scan`** umożliwia skanowanie istniejących obrazów Docker za pomocą nazwy lub identyfikatora obrazu. Na przykład, uruchom poniższe polecenie, aby przeskanować obraz hello-world:
```bash
docker scan hello-world

Testing hello-world...

Organization:      docker-desktop-test
Package manager:   linux
Project name:      docker-image|hello-world
Docker image:      hello-world
Licenses:          enabled

✓ Tested 0 dependencies for known issues, no vulnerable paths found.

Note that we do not currently have vulnerability data for your image.
```
* [**`trivy`**](https://github.com/aquasecurity/trivy)
```bash
trivy -q -f json <ontainer_name>:<tag>
```
* [**`snyk`**](https://docs.snyk.io/snyk-cli/getting-started-with-the-cli)
```bash
snyk container test <image> --json-file-output=<output file> --severity-threshold=high
```
* [**`clair-scanner`**](https://github.com/arminc/clair-scanner)
```bash
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
### Podpisywanie obrazów Docker

Podpisywanie obrazów Docker zapewnia bezpieczeństwo i integralność obrazów używanych w kontenerach. Oto zwięzłe wyjaśnienie:

- **Docker Content Trust** wykorzystuje projekt Notary, oparty na The Update Framework (TUF), do zarządzania podpisywaniem obrazów. Więcej informacji można znaleźć na stronach [Notary](https://github.com/docker/notary) i [TUF](https://theupdateframework.github.io).
- Aby aktywować zaufanie do zawartości Dockera, ustaw `export DOCKER_CONTENT_TRUST=1`. Ta funkcja jest domyślnie wyłączona w wersji Dockera 1.10 i nowszych.
- Po włączeniu tej funkcji można pobierać tylko podpisane obrazy. Pierwsze przesyłanie obrazu wymaga ustawienia haseł dla kluczy root i tagowania, a Docker obsługuje również Yubikey w celu zwiększenia bezpieczeństwa. Więcej szczegółów można znaleźć [tutaj](https://blog.docker.com/2015/11/docker-content-trust-yubikey/).
- Próba pobrania niepodpisanego obrazu przy włączonym zaufaniu do zawartości skutkuje błędem "Brak danych zaufania dla najnowszej wersji".
- Podczas przesyłania obrazów po raz kolejny Docker prosi o hasło do klucza repozytorium w celu podpisania obrazu.

Aby zrobić kopię zapasową prywatnych kluczy, użyj polecenia:
```bash
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Podczas przełączania hostów Docker konieczne jest przeniesienie kluczy roota i repozytorium w celu utrzymania operacji.


***

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo tworzyć i **automatyzować przepływy pracy** z wykorzystaniem najbardziej zaawansowanych narzędzi społecznościowych na świecie.\
Otrzymaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Funkcje bezpieczeństwa kontenerów

<details>

<summary>Podsumowanie funkcji bezpieczeństwa kontenerów</summary>

### Główne funkcje izolacji procesu

W środowiskach kontenerowych izolacja projektów i ich procesów jest niezwykle ważna dla bezpieczeństwa i zarządzania zasobami. Oto uproszczone wyjaśnienie kluczowych pojęć:

#### **Namespaces**
- **Cel**: Zapewnienie izolacji zasobów, takich jak procesy, sieć i systemy plików. W szczególności w Dockerze, przestrzenie nazw utrzymują oddzielność procesów kontenera od hosta i innych kontenerów.
- **Użycie `unshare`**: Polecenie `unshare` (lub odpowiednie wywołanie systemowe) jest wykorzystywane do tworzenia nowych przestrzeni nazw, zapewniając dodatkową warstwę izolacji. Jednak podczas gdy Kubernetes nie blokuje tego domyślnie, Docker tak.
- **Ograniczenie**: Tworzenie nowych przestrzeni nazw nie pozwala procesowi powrócić do domyślnych przestrzeni nazw hosta. Aby przeniknąć do przestrzeni nazw hosta, zazwyczaj wymagane jest dostęp do katalogu `/proc` hosta, korzystając z narzędzia `nsenter` do wejścia.

#### **Grupy kontrolne (CGroups)**
- **Funkcja**: Głównie używane do przydzielania zasobów między procesami.
- **Aspekt bezpieczeństwa**: Same grupy kontrolne nie zapewniają izolacji bezpieczeństwa, z wyjątkiem funkcji `release_agent`, która w przypadku niewłaściwej konfiguracji może potencjalnie być wykorzystana do nieautoryzowanego dostępu.

#### **Ograniczenie uprawnień**
- **Znaczenie**: Jest to kluczowa funkcja bezpieczeństwa dla izolacji procesów.
- **Funkcjonalność**: Ogranicza działania, które może wykonać proces roota poprzez odrzucenie określonych uprawnień. Nawet jeśli proces działa z uprawnieniami roota, brak niezbędnych uprawnień uniemożliwia mu wykonanie uprzywilejowanych działań, ponieważ wywołania systemowe zakończą się niepowodzeniem z powodu niewystarczających uprawnień.

Oto **pozostałe uprawnienia** po odrzuceniu pozostałych:

{% code overflow="wrap" %}
```
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
```
{% endcode %}

**Seccomp**

Jest domyślnie włączony w Dockerze. Pomaga **jeszcze bardziej ograniczyć syscalle**, które proces może wywołać.\
**Domyślny profil Seccomp w Dockerze** można znaleźć pod adresem [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)

**AppArmor**

Docker ma szablon, który można aktywować: [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

To pozwoli na ograniczenie uprawnień, syscalle, dostępu do plików i folderów...

</details>

### Namespaces

**Namespaces** to funkcja jądra Linuxa, która **dzieli zasoby jądra** tak, że jedna grupa **procesów widzi** jeden zestaw **zasobów**, podczas gdy **inna** grupa **procesów widzi** inny zestaw zasobów. Funkcja działa poprzez posiadanie tego samego przestrzeni nazw dla zestawu zasobów i procesów, ale te przestrzenie nazw odnoszą się do odrębnych zasobów. Zasoby mogą istnieć w wielu przestrzeniach.

Docker korzysta z następujących przestrzeni nazw jądra Linuxa, aby osiągnąć izolację kontenerów:

* przestrzeń nazw pid
* przestrzeń nazw montowania
* przestrzeń nazw sieciowych
* przestrzeń nazw ipc
* przestrzeń nazw UTS

Aby **uzyskać więcej informacji na temat przestrzeni nazw**, sprawdź następującą stronę:

{% content-ref url="namespaces/" %}
[namespaces](namespaces/)
{% endcontent-ref %}

### cgroups

Funkcja jądra Linuxa **cgroups** umożliwia ograniczenie zasobów, takich jak cpu, pamięć, io, przepustowość sieciowa, dla zestawu procesów. Docker pozwala tworzyć kontenery przy użyciu funkcji cgroup, co umożliwia kontrolę zasobów dla konkretnego kontenera.\
Poniżej przedstawiono przykład kontenera, w którym pamięć przestrzeni użytkownika jest ograniczona do 500 MB, pamięć jądra do 50 MB, udział w CPU do 512, a waga blkio do 400. Udział w CPU to współczynnik kontrolujący użycie CPU przez kontener. Ma domyślną wartość 1024 i mieści się w zakresie od 0 do 1024. Jeśli trzy kontenery mają ten sam udział w CPU wynoszący 1024, każdy kontener może używać maksymalnie 33% CPU w przypadku wystąpienia konfliktu zasobów CPU. Waga blkio to współczynnik kontrolujący operacje wejścia/wyjścia kontenera. Ma domyślną wartość 500 i mieści się w zakresie od 10 do 1000.
```
docker run -it -m 500M --kernel-memory 50M --cpu-shares 512 --blkio-weight 400 --name ubuntu1 ubuntu bash
```
Aby uzyskać cgroup kontenera, można wykonać:
```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```
Aby uzyskać więcej informacji, sprawdź:

{% content-ref url="cgroups.md" %}
[cgroups.md](cgroups.md)
{% endcontent-ref %}

### Uprawnienia

Uprawnienia umożliwiają **dokładniejszą kontrolę nad uprawnieniami, które mogą być udzielone** użytkownikowi root. Docker korzysta z funkcji możliwości jądra Linuxa, aby **ograniczyć operacje, które można wykonać wewnątrz kontenera** niezależnie od rodzaju użytkownika.

Podczas uruchamiania kontenera Docker, **proces odrzuca wrażliwe uprawnienia, które proces mógłby wykorzystać do ucieczki z izolacji**. Ma to na celu zapewnienie, że proces nie będzie w stanie wykonywać wrażliwych działań i uciekać:

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

### Seccomp w Dockerze

Jest to funkcja zabezpieczeń, która umożliwia Dockerowi **ograniczenie syscalls**, które mogą być używane wewnątrz kontenera:

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

### AppArmor w Dockerze

**AppArmor** to ulepszenie jądra, które ogranicza **kontenery** do **ograniczonego** zestawu **zasobów** z **profilami dla poszczególnych programów**:

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}

### SELinux w Dockerze

- **System etykietowania**: SELinux przypisuje unikalną etykietę każdemu procesowi i obiektowi systemu plików.
- **Egzekwowanie zasad**: Egzekwuje zasady bezpieczeństwa, które określają, jakie działania etykieta procesu może wykonywać na innych etykietach w systemie.
- **Etykiety procesów kontenera**: Gdy silniki kontenerów uruchamiają procesy kontenera, zwykle przypisywane jest im ograniczone oznaczenie SELinux, zwykle `container_t`.
- **Etykietowanie plików wewnątrz kontenerów**: Pliki wewnątrz kontenera są zwykle oznaczane jako `container_file_t`.
- **Zasady polityki**: Polityka SELinux przede wszystkim zapewnia, że procesy o etykiecie `container_t` mogą jedynie współdziałać (czytać, pisać, wykonywać) z plikami oznaczonymi jako `container_file_t`.

Ten mechanizm zapewnia, że nawet jeśli proces wewnątrz kontenera zostanie skompromitowany, jest on ograniczony do interakcji tylko z obiektami posiadającymi odpowiednie etykiety, co znacznie ogranicza potencjalne szkody wynikające z takich kompromitacji.

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}

### AuthZ & AuthN

W Dockerze plugin autoryzacji odgrywa kluczową rolę w zabezpieczeniach, decydując, czy zezwolić czy zablokować żądania do demona Docker. Decyzja ta jest podejmowana na podstawie dwóch kluczowych kontekstów:

- **Kontekst uwierzytelniania**: Obejmuje szczegółowe informacje o użytkowniku, takie jak kim są i jak się uwierzytelnili.
- **Kontekst polecenia**: Obejmuje wszystkie istotne dane dotyczące wykonywanego żądania.

Te konteksty pomagają zapewnić, że tylko legalne żądania od uwierzytelnionych użytkowników są przetwarzane, zwiększając tym samym bezpieczeństwo operacji w Dockerze.

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## DoS z kontenera

Jeśli nie ograniczasz poprawnie zasobów, które kontener może wykorzystać, skompromitowany kontener może spowodować DoS hosta, na którym jest uruchomiony.

* CPU DoS
```bash
# stress-ng
sudo apt-get install -y stress-ng && stress-ng --vm 1 --vm-bytes 1G --verify -t 5m

# While loop
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
```
* Atak DoS na pasmo

Atak DoS na pasmo (Bandwidth DoS) polega na zalewaniu sieci dużej ilości danych w celu zablokowania lub znacznego spowolnienia działania systemu. Ten rodzaj ataku ma na celu wykorzystanie całkowitej przepustowości sieci, co prowadzi do niedostępności usług dla prawidłowych użytkowników. Aby przeprowadzić atak DoS na pasmo, atakujący może wykorzystać różne techniki, takie jak generowanie dużej ilości pakietów, wykorzystanie botnetów lub wykorzystanie zasobów chmury do generowania ruchu sieciowego. W rezultacie, system staje się niedostępny lub działa znacznie wolniej, co może prowadzić do poważnych konsekwencji dla organizacji lub użytkowników. Aby zabezpieczyć się przed atakami DoS na pasmo, ważne jest monitorowanie ruchu sieciowego, wdrażanie odpowiednich zabezpieczeń sieciowych i ograniczanie dostępu do zasobów sieciowych.
```bash
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target IP> 4444; done
```
## Interesujące flagi Docker

### Flaga --privileged

Na następnej stronie możesz dowiedzieć się, **co oznacza flaga `--privileged`**:

{% content-ref url="docker-privileged.md" %}
[docker-privileged.md](docker-privileged.md)
{% endcontent-ref %}

### --security-opt

#### no-new-privileges

Jeśli uruchamiasz kontener, w którym atakujący uzyskuje dostęp jako użytkownik o niskich uprawnieniach. Jeśli masz **źle skonfigurowany binarny suid**, atakujący może go wykorzystać i **zwiększyć uprawnienia wewnątrz** kontenera. Co może pozwolić mu na jego uniknięcie.

Uruchomienie kontenera z włączoną opcją **`no-new-privileges`** **zapobiegnie tego rodzaju eskalacji uprawnień**.
```
docker run -it --security-opt=no-new-privileges:true nonewpriv
```
#### Inne

Inne potencjalne zagrożenia związane z bezpieczeństwem Dockera to:

- **Nieaktualne obrazy**: Używanie nieaktualnych obrazów Dockera może prowadzić do wykorzystania znanych podatności. Ważne jest regularne aktualizowanie obrazów, aby uniknąć tych zagrożeń.

- **Niebezpieczne ustawienia kontenera**: Niewłaściwe ustawienia kontenera mogą prowadzić do naruszenia bezpieczeństwa. Należy upewnić się, że kontenery są uruchamiane z minimalnymi uprawnieniami i odpowiednimi ograniczeniami zasobów.

- **Niewłaściwe zarządzanie uprawnieniami**: Nieprawidłowe zarządzanie uprawnieniami może prowadzić do eskalacji uprawnień. Należy upewnić się, że tylko niezbędne uprawnienia są udzielane kontenerom.

- **Niebezpieczne konfiguracje sieciowe**: Niewłaściwe konfiguracje sieciowe mogą prowadzić do nieautoryzowanego dostępu do kontenerów. Należy skonfigurować odpowiednie zabezpieczenia sieciowe, takie jak izolacja sieciowa i ograniczenia dostępu.

- **Niebezpieczne montowanie woluminów**: Nieprawidłowe montowanie woluminów może prowadzić do nieautoryzowanego dostępu do danych. Należy upewnić się, że tylko niezbędne woluminy są montowane i że są odpowiednio zabezpieczone.

- **Niebezpieczne zarządzanie hasłami**: Niewłaściwe zarządzanie hasłami może prowadzić do kompromitacji kontenerów. Należy stosować silne hasła i unikać przechowywania ich w plikach konfiguracyjnych.

- **Niebezpieczne zarządzanie kluczami**: Niewłaściwe zarządzanie kluczami może prowadzić do nieautoryzowanego dostępu do kontenerów. Należy odpowiednio zarządzać kluczami i unikać przechowywania ich w kontenerach.

- **Niebezpieczne wykorzystanie funkcji Docker API**: Niewłaściwe wykorzystanie funkcji Docker API może prowadzić do nieautoryzowanego dostępu do kontenerów. Należy ograniczyć dostęp do funkcji API i stosować autoryzację.

- **Niebezpieczne wykorzystanie funkcji Docker Hub**: Niewłaściwe wykorzystanie funkcji Docker Hub może prowadzić do wykorzystania złośliwego oprogramowania. Należy unikać pobierania obrazów z niezaufanych źródeł.

- **Niebezpieczne wykorzystanie funkcji Docker Compose**: Niewłaściwe wykorzystanie funkcji Docker Compose może prowadzić do nieautoryzowanego dostępu do kontenerów. Należy ograniczyć dostęp do funkcji Compose i stosować autoryzację.

- **Niebezpieczne wykorzystanie funkcji Docker Swarm**: Niewłaściwe wykorzystanie funkcji Docker Swarm może prowadzić do nieautoryzowanego dostępu do kontenerów. Należy ograniczyć dostęp do funkcji Swarm i stosować autoryzację.

- **Niebezpieczne wykorzystanie funkcji Docker Registry**: Niewłaściwe wykorzystanie funkcji Docker Registry może prowadzić do nieautoryzowanego dostępu do obrazów. Należy ograniczyć dostęp do funkcji Registry i stosować autoryzację.

- **Niebezpieczne wykorzystanie funkcji Docker Volume**: Niewłaściwe wykorzystanie funkcji Docker Volume może prowadzić do nieautoryzowanego dostępu do danych. Należy ograniczyć dostęp do funkcji Volume i stosować autoryzację.

- **Niebezpieczne wykorzystanie funkcji Docker Network**: Niewłaściwe wykorzystanie funkcji Docker Network może prowadzić do nieautoryzowanego dostępu do sieci. Należy ograniczyć dostęp do funkcji Network i stosować autoryzację.

- **Niebezpieczne wykorzystanie funkcji Docker Security**: Niewłaściwe wykorzystanie funkcji Docker Security może prowadzić do naruszenia bezpieczeństwa. Należy stosować odpowiednie zabezpieczenia, takie jak kontrola dostępu i monitorowanie.
```bash
#You can manually add/drop capabilities with
--cap-add
--cap-drop

# You can manually disable seccomp in docker with
--security-opt seccomp=unconfined

# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined

# You can manually disable selinux in docker with
--security-opt label:disable
```
Aby uzyskać więcej opcji **`--security-opt`**, sprawdź: [https://docs.docker.com/engine/reference/run/#security-configuration](https://docs.docker.com/engine/reference/run/#security-configuration)

## Inne kwestie dotyczące bezpieczeństwa

### Zarządzanie tajemnicami: najlepsze praktyki

Niezwykle ważne jest unikanie osadzania tajemnic bezpośrednio w obrazach Docker lub korzystanie z zmiennych środowiskowych, ponieważ te metody ujawniają wrażliwe informacje każdemu, kto ma dostęp do kontenera za pomocą poleceń takich jak `docker inspect` lub `exec`.

**Wolumeny Docker** są bezpieczniejszą alternatywą, zalecaną do dostępu do wrażliwych informacji. Mogą być wykorzystywane jako tymczasowy system plików w pamięci, zmniejszając ryzyko związane z `docker inspect` i logowaniem. Jednak użytkownicy root i ci, którzy mają dostęp do kontenera za pomocą `exec`, wciąż mogą uzyskać dostęp do tajemnic.

**Tajemnice Docker** oferują jeszcze bardziej bezpieczną metodę obsługi wrażliwych informacji. Dla przypadków wymagających tajemnic podczas fazy budowy obrazu, **BuildKit** prezentuje wydajne rozwiązanie z obsługą tajemnic czasu budowy, poprawiające szybkość budowy i zapewniające dodatkowe funkcje.

Aby skorzystać z BuildKit, można go aktywować na trzy sposoby:

1. Za pomocą zmiennej środowiskowej: `export DOCKER_BUILDKIT=1`
2. Poprzez dodanie przedrostka do poleceń: `DOCKER_BUILDKIT=1 docker build .`
3. Poprzez włączenie go domyślnie w konfiguracji Dockera: `{ "features": { "buildkit": true } }`, a następnie restart Dockera.

BuildKit umożliwia korzystanie z tajemnic czasu budowy za pomocą opcji `--secret`, zapewniając, że te tajemnice nie są uwzględniane w pamięci podręcznej budowy obrazu ani w końcowym obrazie, za pomocą polecenia:
```bash
docker build --secret my_key=my_value ,src=path/to/my_secret_file .
```
Dla tajemnic potrzebnych w uruchomionym kontenerze, **Docker Compose i Kubernetes** oferują solidne rozwiązania. Docker Compose wykorzystuje klucz `secrets` w definicji usługi do określania plików z tajemnicami, jak pokazano na przykładzie pliku `docker-compose.yml`:
```yaml
version: "3.7"
services:
my_service:
image: centos:7
entrypoint: "cat /run/secrets/my_secret"
secrets:
- my_secret
secrets:
my_secret:
file: ./my_secret_file.txt
```
Ta konfiguracja umożliwia korzystanie z sekretów podczas uruchamiania usług za pomocą Docker Compose.

W środowiskach Kubernetes, sekrety są obsługiwane natywnie i mogą być dalej zarządzane za pomocą narzędzi takich jak [Helm-Secrets](https://github.com/futuresimple/helm-secrets). Role Based Access Controls (RBAC) w Kubernetes wzmacniają bezpieczeństwo zarządzania sekretami, podobnie jak w przypadku Docker Enterprise.

### gVisor

**gVisor** to jądro aplikacji napisane w języku Go, które implementuje znaczną część powierzchni systemu Linux. Zawiera środowisko wykonawcze [Open Container Initiative (OCI)](https://www.opencontainers.org) o nazwie `runsc`, które zapewnia **granice izolacji między aplikacją a jądrem hosta**. Środowisko wykonawcze `runsc` integruje się z Dockerem i Kubernetes, umożliwiając łatwe uruchamianie kontenerów w piaskownicy.

{% embed url="https://github.com/google/gvisor" %}

### Kata Containers

**Kata Containers** to otwarta społeczność, która pracuje nad budową bezpiecznego środowiska wykonawczego dla kontenerów z wykorzystaniem lekkich maszyn wirtualnych, które działają i wydają się jak kontenery, ale zapewniają **silniejszą izolację obciążenia przy użyciu technologii wirtualizacji sprzętowej** jako drugiej warstwy obrony.

{% embed url="https://katacontainers.io/" %}

### Podsumowanie wskazówek

* **Nie używaj flagi `--privileged` ani nie montuj** [**gniazda Dockera wewnątrz kontenera**](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)**.** Gniazdo Dockera umożliwia uruchamianie kontenerów, więc jest łatwym sposobem na pełną kontrolę nad hostem, na przykład poprzez uruchomienie innego kontenera z flagą `--privileged`.
* **Nie uruchamiaj kontenera jako root. Użyj** [**innego użytkownika**](https://docs.docker.com/develop/develop-images/dockerfile\_best-practices/#user) **i** [**przestrzeni nazw użytkownika**](https://docs.docker.com/engine/security/userns-remap/)**.** Root w kontenerze jest taki sam jak na hoście, chyba że jest przemapowany za pomocą przestrzeni nazw użytkownika. Jest tylko lekko ograniczony przez przede wszystkim przestrzenie nazw Linuxa, uprawnienia i grupy kontrolne.
* [**Odrzuć wszystkie uprawnienia**](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) **(`--cap-drop=all`) i włącz tylko te, które są wymagane** (`--cap-add=...`). Wiele obciążeń nie wymaga żadnych uprawnień, a dodawanie ich zwiększa zakres potencjalnego ataku.
* [**Użyj opcji bezpieczeństwa "no-new-privileges"**](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/) **, aby zapobiec procesom zdobywaniu większych uprawnień, na przykład za pomocą binarnych plików suid.**
* [**Ogranicz zasoby dostępne dla kontenera**](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources)**.** Limity zasobów mogą chronić maszynę przed atakami typu odmowa usługi.
* **Dostosuj profile** [**seccomp**](https://docs.docker.com/engine/security/seccomp/)**,** [**AppArmor**](https://docs.docker.com/engine/security/apparmor/) **(lub SELinux)**, aby ograniczyć dostępne działania i wywołania systemowe dla kontenera do minimum wymaganego.
* **Używaj** [**oficjalnych obrazów Dockera**](https://docs.docker.com/docker-hub/official\_images/) **i wymagaj podpisów** lub buduj własne na ich podstawie. Nie dziedzicz lub nie używaj obrazów z [tylnymi drzwiami](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/). Przechowuj również klucze roota i hasło w bezpiecznym miejscu. Docker planuje zarządzać kluczami za pomocą UCP.
* **Regularnie** **odbudowuj** swoje obrazy, aby **zastosować łatki zabezpieczeń na hoście i obrazach**.
* Mądrze **zarządzaj swoimi sekretami**, aby utrudnić atakującemu dostęp do nich.
* Jeśli **udsłaniasz demona Dockera, użyj protokołu HTTPS** z uwierzytelnianiem klienta i serwera.
* W pliku Dockerfile **preferuj COPY zamiast ADD**. ADD automatycznie rozpakowuje pliki skompresowane i może kopiować pliki z adresów URL. COPY nie ma tych możliwości. W miarę możliwości unikaj używania ADD, aby nie być podatnym na ataki za pośrednictwem zdalnych adresów URL i plików ZIP.
* Używaj **oddzielnych kontenerów dla każdej mikrousługi**.
* **Nie umieszczaj ssh** wewnątrz kontenera, można użyć "docker exec" do połączenia SSH z kontenerem.
* Używaj **mniejszych** obrazów kontenerowych.

## Ucieczka z Dockera / Eskalacja uprawnień

Jeśli jesteś **wewnątrz kontenera Dockera** lub masz dostęp do użytkownika w **grupie docker**, możesz spróbować **uciec i eskalować uprawnienia**:

{% content-ref url="docker-breakout-privilege-escalation/" %}
[docker-breakout-privilege-escalation](docker-breakout-privilege-escalation/)
{% endcontent-ref %}

## Ominięcie autoryzacji pluginu uwierzytelniania Dockera

Jeśli masz dostęp do gniazda Dockera lub masz dostęp do użytkownika w **grupie docker, ale twoje działania są ograniczone przez plugin uwierzytelniania Dockera**, sprawdź, czy możesz go **ominąć**:

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## Utrudnianie ataków na Docker

* Narzędzie [**docker-bench-security**](https://github.com/docker/docker-bench-security) to skrypt, który sprawdza dziesiątki powszechnych najlepszych praktyk dotyczących wdrażania kontenerów Dockera w środowisku produkcyjnym. Testy są zautomatyzowane i oparte na [CIS Docker Benchmark v1.3.1](https://www.cisecurity.org/benchmark/docker/).\
Narzędzie należy uruchomić na hoście z uruchomionym Dockerem lub w kontenerze z wystarczającymi uprawnieniami. Dowiedz się, **jak go uruchomić w pliku README:** [**https://github.com/docker/docker-bench-security**](https://github.com/docker/docker-bench-security).

## Odnośniki

* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/
Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.
