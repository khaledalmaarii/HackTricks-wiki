# macOS AppleFS

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
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## Apple File System (APFS)

**Apple File System (APFS)** es un sistema de archivos moderno diseñado para reemplazar el Hierarchical File System Plus (HFS+). Su desarrollo fue impulsado por la necesidad de **mejorar el rendimiento, la seguridad y la eficiencia**.

Algunas características notables de APFS incluyen:

1. **Compartición de Espacio**: APFS permite que múltiples volúmenes **compartan el mismo almacenamiento libre subyacente** en un solo dispositivo físico. Esto permite una utilización del espacio más eficiente, ya que los volúmenes pueden crecer y reducirse dinámicamente sin necesidad de redimensionamiento manual o reparticionamiento.
1. Esto significa, en comparación con particiones tradicionales en discos de archivos, **que en APFS diferentes particiones (volúmenes) comparten todo el espacio del disco**, mientras que una partición regular generalmente tenía un tamaño fijo.
2. **Instantáneas**: APFS admite **la creación de instantáneas**, que son instancias **de solo lectura** y en un momento dado del sistema de archivos. Las instantáneas permiten copias de seguridad eficientes y fáciles retrocesos del sistema, ya que consumen un almacenamiento adicional mínimo y pueden ser creadas o revertidas rápidamente.
3. **Clones**: APFS puede **crear clones de archivos o directorios que comparten el mismo almacenamiento** que el original hasta que se modifique el clon o el archivo original. Esta característica proporciona una forma eficiente de crear copias de archivos o directorios sin duplicar el espacio de almacenamiento.
4. **Cifrado**: APFS **admite nativamente el cifrado de disco completo** así como el cifrado por archivo y por directorio, mejorando la seguridad de los datos en diferentes casos de uso.
5. **Protección contra Fallos**: APFS utiliza un **esquema de metadatos de copia en escritura que asegura la consistencia del sistema de archivos** incluso en casos de pérdida repentina de energía o fallos del sistema, reduciendo el riesgo de corrupción de datos.

En general, APFS ofrece un sistema de archivos más moderno, flexible y eficiente para dispositivos Apple, con un enfoque en mejorar el rendimiento, la fiabilidad y la seguridad.
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

El volumen `Data` está montado en **`/System/Volumes/Data`** (puedes verificar esto con `diskutil apfs list`).

La lista de firmlinks se puede encontrar en el archivo **`/usr/share/firmlinks`**.
```bash
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
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

{% endhint %}
</details>
{% endhint %}
