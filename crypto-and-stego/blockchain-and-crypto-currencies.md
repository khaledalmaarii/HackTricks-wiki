{% hint style="success" %}
Aprende y practica Hacking en AWS: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Entrenamiento HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Entrenamiento HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* ¡Consulta los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}


## Conceptos Básicos

- Los **Contratos Inteligentes** se definen como programas que se ejecutan en una cadena de bloques cuando se cumplen ciertas condiciones, automatizando la ejecución de acuerdos sin intermediarios.
- Las **Aplicaciones Descentralizadas (dApps)** se basan en contratos inteligentes, presentando una interfaz de usuario amigable y un backend transparente y auditable.
- **Tokens y Monedas** se diferencian en que las monedas sirven como dinero digital, mientras que los tokens representan valor o propiedad en contextos específicos.
- Los **Tokens de Utilidad** otorgan acceso a servicios, y los **Tokens de Seguridad** representan la propiedad de activos.
- **DeFi** significa Finanzas Descentralizadas, ofreciendo servicios financieros sin autoridades centrales.
- **DEX** y **DAOs** se refieren a Plataformas de Intercambio Descentralizadas y Organizaciones Autónomas Descentralizadas, respectivamente.

## Mecanismos de Consenso

Los mecanismos de consenso garantizan validaciones seguras y acordadas de transacciones en la cadena de bloques:
- **Prueba de Trabajo (PoW)** se basa en la potencia computacional para la verificación de transacciones.
- **Prueba de Participación (PoS)** exige a los validadores poseer una cierta cantidad de tokens, reduciendo el consumo de energía en comparación con PoW.

## Aspectos Esenciales de Bitcoin

### Transacciones

Las transacciones de Bitcoin implican la transferencia de fondos entre direcciones. Las transacciones se validan mediante firmas digitales, asegurando que solo el propietario de la clave privada pueda iniciar transferencias.

#### Componentes Clave:

- Las Transacciones Multifirma requieren múltiples firmas para autorizar una transacción.
- Las transacciones constan de **entradas** (origen de los fondos), **salidas** (destino), **tarifas** (pagadas a los mineros) y **scripts** (reglas de la transacción).

### Red Lightning

Busca mejorar la escalabilidad de Bitcoin al permitir múltiples transacciones dentro de un canal, enviando solo el estado final a la cadena de bloques.

## Preocupaciones de Privacidad en Bitcoin

Los ataques a la privacidad, como la **Propiedad Común de Entradas** y la **Detección de Direcciones de Cambio UTXO**, explotan patrones de transacciones. Estrategias como los **Mezcladores** y **CoinJoin** mejoran el anonimato al oscurecer los vínculos de transacción entre usuarios.

## Adquisición de Bitcoins de forma Anónima

Los métodos incluyen intercambios en efectivo, minería y el uso de mezcladores. **CoinJoin** mezcla múltiples transacciones para complicar la rastreabilidad, mientras que **PayJoin** disfraza CoinJoins como transacciones regulares para una mayor privacidad.


# Ataques a la Privacidad de Bitcoin

# Resumen de los Ataques a la Privacidad de Bitcoin

En el mundo de Bitcoin, la privacidad de las transacciones y el anonimato de los usuarios son a menudo temas de preocupación. Aquí tienes una visión general simplificada de varios métodos comunes a través de los cuales los atacantes pueden comprometer la privacidad de Bitcoin.

## **Suposición de Propiedad Común de Entradas**

Generalmente es raro que las entradas de diferentes usuarios se combinen en una sola transacción debido a la complejidad involucrada. Por lo tanto, **se asume a menudo que dos direcciones de entrada en la misma transacción pertenecen al mismo propietario**.

## **Detección de Direcciones de Cambio UTXO**

Un UTXO, o **Salida de Transacción No Gastada**, debe ser gastado por completo en una transacción. Si solo una parte se envía a otra dirección, el resto va a una nueva dirección de cambio. Los observadores pueden asumir que esta nueva dirección pertenece al remitente, comprometiendo la privacidad.

### Ejemplo
Para mitigar esto, los servicios de mezcla o el uso de múltiples direcciones pueden ayudar a oscurecer la propiedad.

## **Exposición en Redes Sociales y Foros**

A veces los usuarios comparten sus direcciones de Bitcoin en línea, lo que hace **fácil vincular la dirección con su propietario**.

## **Análisis del Gráfico de Transacciones**

Las transacciones pueden visualizarse como gráficos, revelando conexiones potenciales entre usuarios basadas en el flujo de fondos.

## **Heurística de Entrada Innecesaria (Heurística de Cambio Óptimo)**

Esta heurística se basa en analizar transacciones con múltiples entradas y salidas para adivinar cuál salida es el cambio que vuelve al remitente.

### Ejemplo
```bash
2 btc --> 4 btc
3 btc     1 btc
```
## **Reutilización Forzada de Direcciones**

Los atacantes pueden enviar pequeñas cantidades a direcciones utilizadas previamente, con la esperanza de que el destinatario combine estos con otros inputs en transacciones futuras, vinculando así las direcciones.

### Comportamiento Correcto de la Cartera
Las carteras deben evitar usar monedas recibidas en direcciones ya utilizadas y vacías para evitar esta filtración de privacidad.

## **Otras Técnicas de Análisis de Blockchain**

- **Montos de Pago Exactos:** Las transacciones sin cambio probablemente sean entre dos direcciones propiedad del mismo usuario.
- **Números Redondos:** Un número redondo en una transacción sugiere un pago, siendo el output no redondo probablemente el cambio.
- **Identificación de Carteras:** Diferentes carteras tienen patrones únicos de creación de transacciones, lo que permite a los analistas identificar el software utilizado y potencialmente la dirección de cambio.
- **Correlaciones de Monto y Tiempo:** Revelar tiempos o montos de transacción puede hacer que las transacciones sean rastreables.

## **Análisis de Tráfico**

Al monitorear el tráfico de red, los atacantes pueden potencialmente vincular transacciones o bloques a direcciones IP, comprometiendo la privacidad del usuario. Esto es especialmente cierto si una entidad opera muchos nodos de Bitcoin, mejorando su capacidad para monitorear transacciones.

## Más
Para obtener una lista completa de ataques y defensas de privacidad, visita [Privacidad de Bitcoin en Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).


# Transacciones de Bitcoin Anónimas

## Formas de Obtener Bitcoins de Forma Anónima

- **Transacciones en Efectivo**: Adquirir bitcoins a través de efectivo.
- **Alternativas en Efectivo**: Comprar tarjetas de regalo e intercambiarlas en línea por bitcoins.
- **Minería**: El método más privado para ganar bitcoins es a través de la minería, especialmente cuando se hace solo, ya que los grupos de minería pueden conocer la dirección IP del minero. [Información sobre Grupos de Minería](https://en.bitcoin.it/wiki/Pooled_mining)
- **Robo**: Teóricamente, robar bitcoins podría ser otro método para adquirirlos de forma anónima, aunque es ilegal y no se recomienda.

## Servicios de Mezcla

Al usar un servicio de mezcla, un usuario puede **enviar bitcoins** y recibir **diferentes bitcoins a cambio**, lo que dificulta rastrear al propietario original. Sin embargo, esto requiere confiar en que el servicio no guarde registros y realmente devuelva los bitcoins. Opciones de mezcla alternativas incluyen casinos de Bitcoin.

## CoinJoin

**CoinJoin** fusiona múltiples transacciones de diferentes usuarios en una sola, complicando el proceso para cualquiera que intente igualar los inputs con los outputs. A pesar de su efectividad, las transacciones con tamaños de input y output únicos aún pueden ser potencialmente rastreadas.

Ejemplos de transacciones que pueden haber utilizado CoinJoin incluyen `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` y `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Para obtener más información, visita [CoinJoin](https://coinjoin.io/en). Para un servicio similar en Ethereum, echa un vistazo a [Tornado Cash](https://tornado.cash), que anonimiza transacciones con fondos de mineros.

## PayJoin

Una variante de CoinJoin, **PayJoin** (o P2EP), disfraza la transacción entre dos partes (por ejemplo, un cliente y un comerciante) como una transacción regular, sin la característica distintiva de outputs iguales de CoinJoin. Esto lo hace extremadamente difícil de detectar y podría invalidar la heurística común de propiedad de input utilizada por entidades de vigilancia de transacciones.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Las transacciones como la anterior podrían ser PayJoin, mejorando la privacidad mientras permanecen indistinguibles de las transacciones estándar de bitcoin.

**La utilización de PayJoin podría interrumpir significativamente los métodos tradicionales de vigilancia**, lo que lo convierte en un desarrollo prometedor en la búsqueda de la privacidad transaccional.


# Mejores Prácticas para la Privacidad en Criptomonedas

## **Técnicas de Sincronización de Billeteras**

Para mantener la privacidad y seguridad, la sincronización de billeteras con la cadena de bloques es crucial. Destacan dos métodos:

- **Nodo completo**: Al descargar toda la cadena de bloques, un nodo completo garantiza la máxima privacidad. Todas las transacciones realizadas se almacenan localmente, lo que hace imposible que los adversarios identifiquen en qué transacciones o direcciones está interesado el usuario.
- **Filtrado de bloques del lado del cliente**: Este método implica crear filtros para cada bloque en la cadena de bloques, permitiendo a las billeteras identificar transacciones relevantes sin exponer intereses específicos a los observadores de la red. Las billeteras ligeras descargan estos filtros, solo obteniendo bloques completos cuando se encuentra una coincidencia con las direcciones del usuario.

## **Utilización de Tor para Anonimato**

Dado que Bitcoin opera en una red peer-to-peer, se recomienda utilizar Tor para enmascarar su dirección IP, mejorando la privacidad al interactuar con la red.

## **Prevención de la Reutilización de Direcciones**

Para salvaguardar la privacidad, es vital utilizar una nueva dirección para cada transacción. La reutilización de direcciones puede comprometer la privacidad al vincular transacciones a la misma entidad. Las billeteras modernas desalientan la reutilización de direcciones a través de su diseño.

## **Estrategias para la Privacidad de Transacciones**

- **Múltiples transacciones**: Dividir un pago en varias transacciones puede oscurecer el monto de la transacción, frustrando los ataques a la privacidad.
- **Evitar el cambio**: Optar por transacciones que no requieran salidas de cambio mejora la privacidad al interrumpir los métodos de detección de cambio.
- **Múltiples salidas de cambio**: Si evitar el cambio no es factible, generar múltiples salidas de cambio aún puede mejorar la privacidad.

# **Monero: Un Faro de Anonimato**

Monero aborda la necesidad de anonimato absoluto en transacciones digitales, estableciendo un alto estándar de privacidad.

# **Ethereum: Gas y Transacciones**

## **Comprensión de Gas**

El gas mide el esfuerzo computacional necesario para ejecutar operaciones en Ethereum, con un precio en **gwei**. Por ejemplo, una transacción que cuesta 2,310,000 gwei (o 0.00231 ETH) implica un límite de gas y una tarifa base, con una propina para incentivar a los mineros. Los usuarios pueden establecer una tarifa máxima para asegurarse de no pagar de más, con el exceso reembolsado.

## **Ejecución de Transacciones**

Las transacciones en Ethereum involucran un remitente y un destinatario, que pueden ser direcciones de usuario o contratos inteligentes. Requieren una tarifa y deben ser minadas. La información esencial en una transacción incluye el destinatario, la firma del remitente, el valor, datos opcionales, límite de gas y tarifas. Notablemente, la dirección del remitente se deduce de la firma, eliminando la necesidad de incluirla en los datos de la transacción.

Estas prácticas y mecanismos son fundamentales para cualquier persona que desee involucrarse con criptomonedas mientras prioriza la privacidad y la seguridad.


## Referencias

* [https://en.wikipedia.org/wiki/Proof\_of\_stake](https://en.wikipedia.org/wiki/Proof\_of\_stake)
* [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
* [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
* [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
* [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
* [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced\_address\_reuse)
