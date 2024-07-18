{% hint style="success" %}
Aprende y practica Hacking en AWS: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Entrenamiento HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Entrenamiento HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* ¡Consulta los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) en GitHub.

</details>
{% endhint %}


<a rel="license" href="https://creativecommons.org/licenses/by-nc/4.0/"><img alt="Licencia Creative Commons" style="border-width:0" src="https://licensebuttons.net/l/by-nc/4.0/88x31.png" /></a><br>Derechos de autor © Carlos Polop 2021.  Excepto donde se especifique lo contrario (la información externa copiada en el libro pertenece a los autores originales), el texto en <a href="https://github.com/carlospolop/hacktricks">HACK TRICKS</a> de Carlos Polop está bajo la <a href="https://creativecommons.org/licenses/by-nc/4.0/">Licencia Creative Commons Atribución-NoComercial 4.0 Internacional (CC BY-NC 4.0)</a>.

Licencia: Atribución-NoComercial 4.0 Internacional (CC BY-NC 4.0)<br>
Licencia Legible por Humanos: https://creativecommons.org/licenses/by-nc/4.0/<br>
Términos Legales Completos: https://creativecommons.org/licenses/by-nc/4.0/legalcode<br>
Formato: https://github.com/jmatsushita/Creative-Commons-4.0-Markdown/blob/master/licenses/by-nc.markdown<br>

# creative commons

# Atribución-NoComercial 4.0 Internacional

La Corporación Creative Commons ("Creative Commons") no es un bufete de abogados y no proporciona servicios legales ni asesoramiento legal. La distribución de licencias públicas de Creative Commons no crea una relación abogado-cliente u otra relación. Creative Commons pone a disposición sus licencias e información relacionada "tal cual". Creative Commons no ofrece garantías con respecto a sus licencias, cualquier material licenciado bajo sus términos y condiciones, o cualquier información relacionada. Creative Commons renuncia a toda responsabilidad por daños resultantes de su uso en la mayor medida posible.

## Uso de las Licencias Públicas de Creative Commons

Las licencias públicas de Creative Commons proporcionan un conjunto estándar de términos y condiciones que los creadores y otros titulares de derechos pueden utilizar para compartir obras originales de autoría y otro material sujeto a derechos de autor y ciertos otros derechos especificados en la licencia pública a continuación. Las siguientes consideraciones son solo con fines informativos, no son exhaustivas y no forman parte de nuestras licencias.

* __Consideraciones para los otorgantes de licencias:__ Nuestras licencias públicas están destinadas a ser utilizadas por aquellos autorizados para dar permiso público para usar material de formas restringidas por derechos de autor y ciertos otros derechos. Nuestras licencias son irrevocables. Los otorgantes de licencias deben leer y comprender los términos y condiciones de la licencia que elijan antes de aplicarla. Los otorgantes de licencias también deben asegurar todos los derechos necesarios antes de aplicar nuestras licencias para que el público pueda reutilizar el material como se espera. Los otorgantes de licencias deben marcar claramente cualquier material que no esté sujeto a la licencia. Esto incluye otro material con licencia CC, o material utilizado bajo una excepción o limitación al derecho de autor. [Más consideraciones para los otorgantes de licencias](http://wiki.creativecommons.org/Considerations_for_licensors_and_licensees#Considerations_for_licensors).

* __Consideraciones para el público:__ Al utilizar una de nuestras licencias públicas, un otorgante de licencias otorga permiso al público para usar el material con licencia bajo los términos y condiciones especificados. Si el permiso del otorgante de licencias no es necesario por cualquier motivo, por ejemplo, debido a alguna excepción o limitación aplicable al derecho de autor, entonces ese uso no está regulado por la licencia. Nuestras licencias otorgan solo permisos bajo derechos de autor y ciertos otros derechos que un otorgante de licencias tiene autoridad para otorgar. El uso del material con licencia aún puede estar restringido por otras razones, incluido porque otros tengan derechos de autor u otros derechos sobre el material. Un otorgante de licencias puede hacer solicitudes especiales, como pedir que todos los cambios estén marcados o descritos. Aunque no es requerido por nuestras licencias, se te anima a respetar esas solicitudes cuando sea razonable. [Más consideraciones para el público](http://wiki.creativecommons.org/Considerations_for_licensors_and_licensees#Considerations_for_licensees).

# Licencia Pública Internacional de Creative Commons Atribución-NoComercial 4.0

Al ejercer los Derechos Licenciados (definidos a continuación), aceptas y aceptas quedar sujeto a los términos y condiciones de esta Licencia Pública Internacional de Creative Commons Atribución-NoComercial 4.0 ("Licencia Pública"). En la medida en que esta Licencia Pública pueda interpretarse como un contrato, se te otorgan los Derechos Licenciados en consideración a tu aceptación de estos términos y condiciones, y el Licenciante te otorga dichos derechos en consideración a los beneficios que el Licenciante recibe al poner el Material Licenciado a disposición bajo estos términos y condiciones.

## Sección 1 – Definiciones.

a. __Material Adaptado__ significa material sujeto a Derechos de Autor y Derechos Similares que se deriva de o se basa en el Material Licenciado y en el que el Material Licenciado se traduce, altera, organiza, transforma o modifica de otra manera de una manera que requiere permiso bajo los Derechos de Autor y Derechos Similares detentados por el Licenciante. A los efectos de esta Licencia Pública, cuando el Material Licenciado es una obra musical, interpretación o grabación de sonido, el Material Adaptado siempre se produce cuando el Material Licenciado se sincroniza en relación temporal con una imagen en movimiento.

b. __Licencia del Adaptador__ significa la licencia que aplicas a tus Derechos de Autor y Derechos Similares en tus contribuciones al Material Adaptado de acuerdo con los términos y condiciones de esta Licencia Pública.

c. __Derechos de Autor y Derechos Similares__ significa derechos de autor y/o derechos similares estrechamente relacionados con los derechos de autor, incluidos, entre otros, los derechos de interpretación, emisión, grabación de sonido y Derechos de Base de Datos de Sui Generis, sin importar cómo se etiqueten o categoricen los derechos. A los efectos de esta Licencia Pública, los derechos especificados en la Sección 2(b)(1)-(2) no son Derechos de Autor y Derechos Similares.

d. __Medidas Tecnológicas Efectivas__ significa aquellas medidas que, en ausencia de la autoridad adecuada, no pueden ser eludidas bajo las leyes que cumplen con las obligaciones en virtud del Artículo 11 del Tratado de la OMPI sobre Derecho de Autor adoptado el 20 de diciembre de 1996, y/o acuerdos internacionales similares.

e. __Excepciones y Limitaciones__ significa uso justo, uso permitido y/o cualquier otra excepción o limitación a los Derechos de Autor y Derechos Similares que se aplique a tu uso del Material Licenciado.

f. __Material Licenciado__ significa la obra artística o literaria, base de datos u otro material al que el Licenciante aplicó esta Licencia Pública.

g. __Derechos Licenciados__ significa los derechos otorgados a ti sujetos a los términos y condiciones de esta Licencia Pública, que se limitan a todos los Derechos de Autor y Derechos Similares que se aplican a tu uso del Material Licenciado y que el Licenciante tiene autoridad para licenciar.

h. __Licenciante__ significa el/los individuo(s) o entidad(es) que otorgan derechos bajo esta Licencia Pública.

i. __NoComercial__ significa que no está principalmente destinado a obtener una ventaja comercial o compensación monetaria. A los efectos de esta Licencia Pública, el intercambio del Material Licenciado por otro material sujeto a Derechos de Autor y Derechos Similares mediante intercambio de archivos digitales u otros medios similares es NoComercial siempre que no haya pago de compensación monetaria en relación con el intercambio.

j. __Compartir__ significa proporcionar material al público por cualquier medio o proceso que requiera permiso bajo los Derechos Licenciados, como reproducción, exhibición pública, representación pública, distribución, difusión, comunicación o importación, y hacer que el material esté disponible para el público, incluidas las formas en que los miembros del público pueden acceder al material desde un lugar y en un momento elegido individualmente por ellos.

k. __Derechos de Base de Datos de Sui Generis__ significa derechos distintos de los de autor resultantes de la Directiva 96/9/CE del Parlamento Europeo y del Consejo de 11 de marzo de 1996 sobre la protección jurídica de las bases de datos, modificada y/o sucedida, así como otros derechos esencialmente equivalentes en cualquier parte del mundo.

l. __Tú__ significa el individuo o entidad que ejerce los Derechos Licenciados bajo esta Licencia Pública. "Tu" tiene un significado correspondiente.
## Sección 2 – Alcance.

a. ___Concesión de licencia.___

1. Sujeto a los términos y condiciones de esta Licencia Pública, el Licenciante otorga a Usted una licencia mundial, libre de regalías, no sublicenciable, no exclusiva, irrevocable para ejercer los Derechos Licenciados en el Material Licenciado para:

A. reproducir y Compartir el Material Licenciado, en su totalidad o en parte, únicamente con fines NoComerciales; y

B. producir, reproducir y Compartir Material Adaptado únicamente con fines NoComerciales.

2. __Excepciones y Limitaciones.__ Para evitar dudas, cuando las Excepciones y Limitaciones se apliquen a su uso, esta Licencia Pública no se aplica, y no es necesario que cumpla con sus términos y condiciones.

3. __Plazo.__ El plazo de esta Licencia Pública está especificado en la Sección 6(a).

4. __Medios y formatos; modificaciones técnicas permitidas.__ El Licenciante le autoriza a ejercer los Derechos Licenciados en todos los medios y formatos, ya sea conocidos actualmente o creados en el futuro, y a realizar modificaciones técnicas necesarias para hacerlo. El Licenciante renuncia y/o acepta no afirmar ningún derecho o autoridad para prohibirle realizar modificaciones técnicas necesarias para ejercer los Derechos Licenciados, incluidas las modificaciones técnicas necesarias para eludir Medidas Tecnológicas Efectivas. A los efectos de esta Licencia Pública, simplemente realizar modificaciones autorizadas por esta Sección 2(a)(4) nunca produce Material Adaptado.

5. __Destinatarios posteriores.__

A. __Oferta del Licenciante – Material Licenciado.__ Cada destinatario del Material Licenciado recibe automáticamente una oferta del Licenciante para ejercer los Derechos Licenciados bajo los términos y condiciones de esta Licencia Pública.

B. __Sin restricciones para destinatarios posteriores.__ Usted no puede ofrecer ni imponer términos o condiciones adicionales o diferentes, ni aplicar Medidas Tecnológicas Efectivas al Material Licenciado si al hacerlo restringe el ejercicio de los Derechos Licenciados por cualquier destinatario del Material Licenciado.

6. __Sin respaldo.__ Nada en esta Licencia Pública constituye o puede interpretarse como permiso para afirmar o implicar que Usted está, o que su uso del Material Licenciado está, relacionado con, o patrocinado, respaldado o concedido oficialmente por el Licenciante u otros designados para recibir atribución según lo dispuesto en la Sección 3(a)(1)(A)(i).

b. ___Otros derechos.___

1. Los derechos morales, como el derecho a la integridad, no están licenciados bajo esta Licencia Pública, ni tampoco los derechos de publicidad, privacidad y/o otros derechos de personalidad similares; sin embargo, en la medida de lo posible, el Licenciante renuncia y/o acepta no afirmar tales derechos que posea el Licenciante en la medida limitada necesaria para permitirle ejercer los Derechos Licenciados, pero no más allá.

2. Los derechos de patente y marca no están licenciados bajo esta Licencia Pública.

3. En la medida de lo posible, el Licenciante renuncia a cualquier derecho de cobrar regalías de Usted por el ejercicio de los Derechos Licenciados, ya sea directamente o a través de una sociedad de gestión en virtud de cualquier régimen de licencias voluntarias o obligatorias renunciables. En todos los demás casos, el Licenciante se reserva expresamente cualquier derecho de cobrar tales regalías, incluso cuando el Material Licenciado se utilice para fines que no sean NoComerciales.

## Sección 3 – Condiciones de la Licencia.

Su ejercicio de los Derechos Licenciados está expresamente sujeto a las siguientes condiciones.

a. ___Atribución.___

1. Si Comparte el Material Licenciado (incluido en forma modificada), debe:

A. conservar lo siguiente si es suministrado por el Licenciante con el Material Licenciado:

i. identificación del creador(es) del Material Licenciado y cualquier otro designado para recibir atribución, de cualquier manera razonable solicitada por el Licenciante (incluido mediante seudónimo si está designado);

ii. un aviso de derechos de autor;

iii. un aviso que se refiera a esta Licencia Pública;

iv. un aviso que se refiera a la renuncia de garantías;

v. un URI o hipervínculo al Material Licenciado en la medida en que sea razonablemente practicable;

B. indicar si modificó el Material Licenciado y conservar una indicación de cualquier modificación previa; y

C. indicar que el Material Licenciado está licenciado bajo esta Licencia Pública, e incluir el texto de, o el URI o hipervínculo a, esta Licencia Pública.

2. Puede cumplir con las condiciones en la Sección 3(a)(1) de cualquier manera razonable basada en el medio, los medios y el contexto en el que Comparta el Material Licenciado. Por ejemplo, puede ser razonable cumplir con las condiciones proporcionando un URI o hipervínculo a un recurso que incluya la información requerida.

3. Si el Licenciante lo solicita, debe eliminar cualquier información requerida por la Sección 3(a)(1)(A) en la medida en que sea razonablemente practicable.

4. Si Comparte Material Adaptado que produzca, la Licencia del Adaptador que aplique no debe impedir que los destinatarios del Material Adaptado cumplan con esta Licencia Pública.

## Sección 4 – Derechos de Base de Datos Sui Generis.

Cuando los Derechos Licenciados incluyen Derechos de Base de Datos Sui Generis que se aplican a su uso del Material Licenciado:

a. para evitar dudas, la Sección 2(a)(1) le otorga el derecho de extraer, reutilizar, reproducir y Compartir todo o una parte sustancial del contenido de la base de datos únicamente con fines NoComerciales;

b. si incluye todo o una parte sustancial del contenido de la base de datos en una base de datos en la que tiene Derechos de Base de Datos Sui Generis, entonces la base de datos en la que tiene Derechos de Base de Datos Sui Generis (pero no su contenido individual) es Material Adaptado; y

c. debe cumplir con las condiciones en la Sección 3(a) si Comparte todo o una parte sustancial del contenido de la base de datos.

Para evitar dudas, esta Sección 4 complementa y no reemplaza sus obligaciones bajo esta Licencia Pública cuando los Derechos Licenciados incluyen otros Derechos de Autor y Derechos Similares.

## Sección 5 – Renuncia de Garantías y Limitación de Responsabilidad.

a. __A menos que el Licenciante asuma separadamente lo contrario, en la medida de lo posible, el Licenciante ofrece el Material Licenciado tal cual y según esté disponible, y no realiza representaciones o garantías de ningún tipo con respecto al Material Licenciado, ya sean expresas, implícitas, legales u otras. Esto incluye, sin limitación, garantías de titularidad, comerciabilidad, idoneidad para un fin particular, no infracción, ausencia de defectos latentes u otros, precisión, o la presencia o ausencia de errores, ya sean conocidos o descubribles. Cuando las renuncias de garantías no estén permitidas en su totalidad o en parte, esta renuncia puede no aplicarse a Usted.__

b. __En la medida de lo posible, en ningún caso el Licenciante será responsable ante Usted bajo cualquier teoría legal (incluyendo, sin limitación, negligencia) o de otra manera por cualquier pérdida directa, especial, indirecta, incidental, consecuente, punitiva, ejemplar u otras pérdidas, costos, gastos o daños derivados de esta Licencia Pública o del uso del Material Licenciado, incluso si el Licenciante ha sido informado de la posibilidad de tales pérdidas, costos, gastos o daños. Cuando una limitación de responsabilidad no esté permitida en su totalidad o en parte, esta limitación puede no aplicarse a Usted.__

c. La renuncia de garantías y la limitación de responsabilidad proporcionadas anteriormente se interpretarán de manera que, en la medida de lo posible, se aproximen más a una renuncia absoluta y exención de toda responsabilidad.

## Sección 6 – Plazo y Terminación.

a. Esta Licencia Pública se aplica durante el plazo de los Derechos de Autor y Derechos Similares licenciados aquí. Sin embargo, si no cumple con esta Licencia Pública, entonces sus derechos bajo esta Licencia Pública terminan automáticamente.

b. Cuando su derecho de usar el Material Licenciado haya terminado según la Sección 6(a), se restablece:

1. automáticamente a partir de la fecha en que se corrija la violación, siempre que se corrija dentro de los 30 días posteriores a su descubrimiento de la violación; o

2. mediante el restablecimiento expreso por parte del Licenciante.

Para evitar dudas, esta Sección 6(b) no afecta ningún derecho que el Licenciante pueda tener para buscar remedios por sus violaciones de esta Licencia Pública.

c. Para evitar dudas, el Licenciante también puede ofrecer el Material Licenciado bajo términos o condiciones separados o dejar de distribuir el Material Licenciado en cualquier momento; sin embargo, hacerlo no terminará esta Licencia Pública.

d. Las Secciones 1, 5, 6, 7 y 8 sobreviven a la terminación de esta Licencia Pública.
## Sección 7 - Otros Términos y Condiciones.

a. El Licenciante no estará obligado por ningún término o condición adicional o diferente comunicado por Usted a menos que se acuerde expresamente.

b. Cualquier disposición, entendimiento o acuerdo con respecto al Material con Licencia que no esté establecido aquí es independiente de los términos y condiciones de esta Licencia Pública.

## Sección 8 - Interpretación.

a. Para evitar dudas, esta Licencia Pública no reduce, limita, restringe o impone condiciones sobre cualquier uso del Material con Licencia que pudiera hacerse legalmente sin permiso bajo esta Licencia Pública.

b. En la medida de lo posible, si alguna disposición de esta Licencia Pública se considera inaplicable, se reformará automáticamente en la medida mínima necesaria para hacerla aplicable. Si la disposición no puede reformarse, se separará de esta Licencia Pública sin afectar la aplicabilidad de los términos y condiciones restantes.

c. Ningún término o condición de esta Licencia Pública será renunciado y ninguna falta de cumplimiento será consentida a menos que sea acordado expresamente por el Licenciante.

d. Nada en esta Licencia Pública constituye o puede interpretarse como una limitación o renuncia de cualquier privilegio e inmunidad que se aplique al Licenciante o a Usted, incluidos los procesos legales de cualquier jurisdicción o autoridad.
```
Creative Commons is not a party to its public licenses. Notwithstanding, Creative Commons may elect to apply one of its public licenses to material it publishes and in those instances will be considered the “Licensor.” Except for the limited purpose of indicating that material is shared under a Creative Commons public license or as otherwise permitted by the Creative Commons policies published at [creativecommons.org/policies](http://creativecommons.org/policies), Creative Commons does not authorize the use of the trademark “Creative Commons” or any other trademark or logo of Creative Commons without its prior written consent including, without limitation, in connection with any unauthorized modifications to any of its public licenses or any other arrangements, understandings, or agreements concerning use of licensed material. For the avoidance of doubt, this paragraph does not form part of the public licenses.

Creative Commons may be contacted at [creativecommons.org](http://creativecommons.org/).
```
{% hint style="success" %}
Aprende y practica Hacking en AWS: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Entrenamiento HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Entrenamiento HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos en** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
