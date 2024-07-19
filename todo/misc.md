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


En una respuesta de ping TTL:\
127 = Windows\
254 = Cisco\
Lo demás, algún linux

$1$- md5\
$2$or $2a$ - Blowfish\
$5$- sha256\
$6$- sha512

Si no sabes qué hay detrás de un servicio, intenta hacer una solicitud HTTP GET.

**Escaneos UDP**\
nc -nv -u -z -w 1 \<IP> 160-16

Se envía un paquete UDP vacío a un puerto específico. Si el puerto UDP está abierto, no se envía respuesta desde la máquina objetivo. Si el puerto UDP está cerrado, se debería enviar un paquete ICMP de puerto inalcanzable desde la máquina objetivo.\

El escaneo de puertos UDP a menudo es poco confiable, ya que los firewalls y routers pueden descartar paquetes ICMP.\
Esto puede llevar a falsos positivos en tu escaneo, y regularmente verás escaneos de puertos UDP mostrando todos los puertos UDP abiertos en una máquina escaneada.\
La mayoría de los escáneres de puertos no escanean todos los puertos disponibles, y generalmente tienen una lista preestablecida de “puertos interesantes” que se escanean.

# CTF - Tricks

En **Windows** usa **Winzip** para buscar archivos.\
**Flujos de datos alternativos**: _dir /r | find ":$DATA"_\
```
binwalk --dd=".*" <file> #Extract everything
binwalk -M -e -d=10000 suspicious.pdf #Extract, look inside extracted files and continue extracing (depth of 10000)
```
## Crypto

**featherduster**\


**Basae64**(6—>8) —> 0...9, a...z, A…Z,+,/\
**Base32**(5 —>8) —> A…Z, 2…7\
**Base85** (Ascii85, 7—>8) —> 0...9, a...z, A...Z, ., -, :, +, =, ^, !, /, \*, ?, &, <, >, (, ), \[, ], {, }, @, %, $, #\
**Uuencode** --> Comienza con "_begin \<mode> \<filename>_" y caracteres extraños\
**Xxencoding** --> Comienza con "_begin \<mode> \<filename>_" y B64\
\
**Vigenere** (análisis de frecuencia) —> [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)\
**Scytale** (desplazamiento de caracteres) —> [https://www.dcode.fr/scytale-cipher](https://www.dcode.fr/scytale-cipher)

**25x25 = QR**

factordb.com\
rsatool

Snow --> Ocultar mensajes usando espacios y tabulaciones

# Characters

%E2%80%AE => Carácter RTL (escribe cargas útiles al revés)


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
