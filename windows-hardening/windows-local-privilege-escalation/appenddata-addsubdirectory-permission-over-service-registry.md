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


**La publicación original es** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Resumen

Se encontraron dos claves de registro que eran escribibles por el usuario actual:

- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**

Se sugirió verificar los permisos del servicio **RpcEptMapper** utilizando la **GUI de regedit**, específicamente la pestaña **Permisos efectivos** de la ventana de **Configuración de seguridad avanzada**. Este enfoque permite evaluar los permisos otorgados a usuarios o grupos específicos sin necesidad de examinar cada Entrada de Control de Acceso (ACE) individualmente.

Una captura de pantalla mostró los permisos asignados a un usuario con pocos privilegios, entre los cuales el permiso **Crear subclave** era notable. Este permiso, también conocido como **AppendData/AddSubdirectory**, corresponde con los hallazgos del script.

Se observó la incapacidad de modificar ciertos valores directamente, pero la capacidad de crear nuevas subclaves. Un ejemplo destacado fue un intento de alterar el valor **ImagePath**, que resultó en un mensaje de acceso denegado.

A pesar de estas limitaciones, se identificó un potencial para la escalada de privilegios a través de la posibilidad de aprovechar la subclave **Performance** dentro de la estructura de registro del servicio **RpcEptMapper**, una subclave que no está presente por defecto. Esto podría permitir el registro de DLL y la monitorización del rendimiento.

Se consultó la documentación sobre la subclave **Performance** y su utilización para la monitorización del rendimiento, lo que llevó al desarrollo de una DLL de prueba de concepto. Esta DLL, que demuestra la implementación de las funciones **OpenPerfData**, **CollectPerfData** y **ClosePerfData**, fue probada a través de **rundll32**, confirmando su éxito operativo.

El objetivo era forzar al **servicio de mapeo de puntos finales RPC** a cargar la DLL de rendimiento creada. Las observaciones revelaron que la ejecución de consultas de clase WMI relacionadas con los datos de rendimiento a través de PowerShell resultó en la creación de un archivo de registro, lo que permitió la ejecución de código arbitrario bajo el contexto de **SISTEMA LOCAL**, otorgando así privilegios elevados.

Se subrayaron la persistencia y las posibles implicaciones de esta vulnerabilidad, destacando su relevancia para estrategias de post-explotación, movimiento lateral y evasión de sistemas antivirus/EDR.

Aunque la vulnerabilidad se divulgó inicialmente de manera no intencionada a través del script, se enfatizó que su explotación está restringida a versiones antiguas de Windows (por ejemplo, **Windows 7 / Server 2008 R2**) y requiere acceso local.

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
