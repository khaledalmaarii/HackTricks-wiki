# Analiza forensyczna Docker

<details>

<summary><strong>Nauka hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakowania, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Modyfikacja kontenera

Istnieją podejrzenia, że pewien kontener Docker został skompromitowany:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Możesz łatwo **znaleźć modyfikacje dokonane na tym kontenerze w odniesieniu do obrazu** za pomocą:
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
W poprzedniej komendzie **C** oznacza **Zmienione**, a **A,** **Dodane**.\
Jeśli okaże się, że jakiś interesujący plik, na przykład `/etc/shadow`, został zmodyfikowany, możesz go pobrać z kontenera, aby sprawdzić, czy nie ma w nim działalności złośliwej za pomocą:
```bash
docker cp wordpress:/etc/shadow.
```
Możesz również **porównać go z oryginalnym** uruchamiając nowy kontener i wydobywając plik z niego:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Jeśli okaże się, że **został dodany podejrzany plik**, możesz uzyskać dostęp do kontenera i go sprawdzić:
```bash
docker exec -it wordpress bash
```
## Modyfikacje obrazów

Kiedy otrzymasz wyeksportowany obraz dockera (prawdopodobnie w formacie `.tar`), możesz użyć [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases), aby **wyodrębnić podsumowanie modyfikacji**:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Następnie możesz **rozpakować** obraz i **uzyskać dostęp do blobów**, aby wyszukać podejrzane pliki, które mogłeś znaleźć w historii zmian:
```bash
tar -xf image.tar
```
### Podstawowa analiza

Możesz uzyskać **podstawowe informacje** z obrazu uruchomionego:
```bash
docker inspect <image>
```
Możesz również uzyskać podsumowanie **historii zmian** za pomocą:
```bash
docker history --no-trunc <image>
```
Możesz również wygenerować **dockerfile z obrazu** za pomocą:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Zanurz się

Aby znaleźć dodane/zmodyfikowane pliki w obrazach dockerowych, można również skorzystać z narzędzia [**dive**](https://github.com/wagoodman/dive) (pobierz je z [**wydań**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)):
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
To pozwala Ci **przeglądać różne bloki obrazów Docker** i sprawdzać, które pliki zostały zmodyfikowane/dodane. **Czerwony** oznacza dodany, a **żółty** oznacza zmodyfikowany. Użyj **tabulacji**, aby przejść do innej widoku, a **spacji**, aby zwijać/otwierać foldery.

Za pomocą tego nie będziesz mógł uzyskać dostępu do zawartości różnych etapów obrazu. Aby to zrobić, będziesz musiał **rozpakować każdą warstwę i uzyskać do niej dostęp**.\
Możesz rozpakować wszystkie warstwy obrazu z katalogu, w którym obraz został rozpakowany, wykonując:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Dane uwierzytelniające z pamięci

Zauważ, że gdy uruchamiasz kontener Docker wewnątrz hosta **możesz zobaczyć procesy uruchomione na kontenerze z hosta** po prostu wykonując `ps -ef`

Dlatego (jako root) możesz **wydobyć pamięć procesów** z hosta i wyszukać **dane uwierzytelniające** tak [**jak w poniższym przykładzie**](../../linux-hardening/privilege-escalation/#process-memory).