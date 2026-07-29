# PatchHound

Importador de credenciales + etiquetado de "Owned" para **BloodHound Community Edition (CE)**.

> Inspirado en [knavesec/Max](https://github.com/knavesec/Max)

![screenshot](img/11.png)

---

## TL;DR

- **auth** — inicia sesión en BloodHound CE y almacena en caché un JWT (utilizado por otros comandos para la API).
- **patch** — lee un **potfile** (credenciales crackeadas) + **archivo NTLM**, analiza, genera estadísticas y actualiza los nodos del grafo en Neo4j.  
- **policy** — auditoría de contraseñas offline utilizando el mismo **potfile** + **archivo NTLM**; no requiere Neo4j ni API.
  - Siempre establece:
    - `Patchhound_has_hash` **(bool)**
    - `Patchhound_has_pass` **(bool)** – true cuando se conoce una contraseña crackeada
  - Con `-t/--temp` **también** escribe (valores temporales):
    - `Patchhound_nt`  – hash NTLM
    - `Patchhound_pass` – contraseña en texto plano  
    _Se espera que estos dos sean efímeros; BloodHound CE no persiste las propiedades personalizadas de los nodos a través de los reinicios del contenedor por defecto._
  - Con `-o/--owned` **después** del parcheo, descubre los SIDs elegibles vía **Neo4j** y luego **añade** selectores de "Owned" a través de la **API HTTP v2** de BloodHound.  
    - Las búsquedas (a quién marcar como owned) ocurren **solo en Neo4j**; la API se utiliza **solo** para añadir los selectores de Owned.

Los colores se pueden desactivar con `--no-color`. 
Salida detallada mediante `-v`, amo el modo verbose, no me puedo perder ninguna importación.

![screenshot](img/5.png)

---

## Instalación

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install neo4j requests
```

Los valores predeterminados residen en **`src/conn.py`**:
- `DEFAULT_URI`
- `DEFAULT_USER`
- `DEFAULT_PASS`  (el predeterminado de BH CE es `bloodhoundcommunityedition`)

Puedes anular estos valores directamente mediante los flags de la CLI `--db-uri`, `--db-user` y `--db-pass`.

---

## Uso

### Ayuda
```bash
python3 PatchHound.py --help
python3 PatchHound.py [--no-color] [subcommand] -h
```

### 1) Autenticar (almacena el JWT para otros comandos)
```bash
python3 PatchHound.py auth -u http://localhost:8080/ -U admin -p 'Exclude -p for PassPrompt' [-v]
```
- Escribe un archivo de sesión en: `${TMPDIR}/patchhound.session.json`

### 2) Patch (analiza archivos, establece flags mínimos; escrituras temporales opcionales)
```bash
python3 PatchHound.py patch -c crack.potfile -n ntds.txt [-t] [-o] [-v]
```

**Qué lee**
- `-c/--clears` **potfile** — formato esperado: `<32hex_ntlm>:<password>`  
  - Los valores `$HEX[...]` se decodifican; en modo verbose verás líneas como:
    ```
    nthash:$HEX[hex...]:decoded-password
    ```
  - Cualquier línea que no coincida con el esquema esperado es **excluida** y enumerada (verbose) con un motivo.
- `-n/--ntlm` **archivo de hashes** — consume líneas que contengan uno o más NTLMs de 32 caracteres hex y un token de cuenta:
  - prefiere `DOMAIN\SAM`; captura tokens UPN explícitos cuando están presentes; **sintetiza** el UPN como `SAM@fqdn` cuando es posible.
  - Las líneas que no cumplen el formato son excluidas con sus motivos (verbose).

**Cómo funciona el emparejamiento (Neo4j)**
- Para cada fila candidata intentamos todo esto simultáneamente:
  - `(:User {name})`
  - `(:User).samaccountname`
  - `(:User).userprincipalname | userPrincipalName`
  - `(:AZUser).userprincipalname | userPrincipalName`
  - `(:Computer).samaccountname`
- Las comparaciones para SAM/UPN no distinguen mayúsculas de minúsculas (`toUpper` en ambos lados).  
- Los nodos se desduplican y actualizan de forma idempotente.

**Qué se escribe**
- Siempre:
  - `Patchhound_has_hash = true`
  - `Patchhound_has_pass = (pwd != null)`
- Con `-t/--temp`:
  - `Patchhound_nt = <ntlm>`
  - `Patchhound_pass = <password>`

**Salida**
- No verbosa:
  ```
  [+] JWT valid
  [+] Potfile Check
  [+] NTLM Check
  [+] Neo4j auth OK
  [+] Waiting for Neo4j
  Applying [████████████████████████████] 14598/14598 (100%)
  [+] Updated nodes: 1234
  ```
- El modo verbose también imprime estadísticas detalladas, HEX decodificados y líneas de entrada excluidas.

### 3) Añadir “Owned” vía API (con `-o`)
- Después del parcheo (o incluso cuando no se aplique nada), `-o` hará lo siguiente:
  1. Consultar **Neo4j** en busca de usuarios donde `Patchhound_has_pass = true` y tengan un SID no vacío (`u.objectid`).
  2. Contar cuántos de esos SIDs tienen un SID de `:AZUser` coincidente on-prem (se admiten varios nombres de propiedad).
  3. **Añadir** esos SIDs al **grupo de activos** configurado a través de la API v2 de BHCE.

- No verboso:
  ```
  [+] Waiting for Neo4j and API
  Owned API [████████████████████████████] 1876/1876 (100%)
  [+] Owned API: attempted 1876 selector adds
  ```

- Resumen final verboso (impreso **después** de toda la lógica):
  ```
  [*] Owned summary:
      users_with_password_true  : 1876
      with_sid                  : 1876
      distinct_sids_sent        : 1876
      sids_with_azuser_link     : 0
      asset_group_id            : 2
      example_request:
        PUT http://localhost:8080/api/v2/asset-groups/2/selectors
        payload: [{"selector_name":"Manual","sid":"S-1-5-21-...","action":"add"}]
  ```

---

### 4) Policy (auditoría de contraseñas offline)
```bash
python3 PatchHound.py policy -c crack.potfile -n ntds.txt [-e] [-v]
```

Se ejecuta completamente offline — no requiere Neo4j, ni API, ni sesión.  
Correlaciona el potfile con el volcado NTLM e imprime una auditoría tabular que cubre:

- **Overview** — total de cuentas, crackeadas vs. no crackeadas, contraseñas vacías/en blanco, recuento de contraseñas únicas. Usa `--enabled` para restringir cada informe a entradas marcadas como `(status=Enabled)`.
- **Distribución de longitud de contraseñas** — recuentos agrupados (1-4, 5-7, 8-10, 11-14, 15+ caracteres).
- **Contraseñas más reutilizadas** — contraseñas más compartidas entre cuentas.
- **Cuentas de Servicio / Privilegiadas** — cuentas crackeadas cuyo nombre SAM contiene `svc`, `admin`, `sql`, `backup`, `adm` o `dev`.
- **Patrones recurrentes** — subcadenas más frecuentes (3-12 caracteres) encontradas en las contraseñas (ej. `@123`, `corp`, `2024!`).
- **Uso de caracteres especiales** — tabla de frecuencia por carácter para puntuación/símbolos.

Con `-v`, se añade al final una tabla completa de cada cuenta crackeada y su contraseña.

---

## Flags (actuales)

- `-v, --verbose` — salida detallada (estadísticas, líneas excluidas, decodificación HEX, resúmenes)
- `--no-color` — desactivar salida coloreada/ASCII
- `patch`:
  - `-c, --clears` — ruta al potfile (**requerido**)
  - `-n, --ntlm` — ruta al archivo de hashes NTLM (**requerido**)
  - `-t, --temp` — escribir `Patchhound_nt` y `Patchhound_pass`
  - `-o, --owned` — añadir selectores “Owned” vía API basados en el descubrimiento de Neo4j
  - `--db-uri`, `--db-user`, `--db-pass` — anular los valores predeterminados de conexión de Neo4j
- `auth`:
  - `-u, --url`
  - `-U, --username`
  - `-p, --password`
- `policy`:
  - `-c, --clears` — ruta al potfile (**requerido**)
  - `-n, --ntlm` — ruta al archivo de hashes NTLM (**requerido**)
  - `-e, --enabled` — incluir solo entradas de NTDS marcadas como `(status=Enabled)`

---

## Screenshots

![s1](img/7.png)
![s2](img/8.png)
![s2](img/9.png)
![s3](img/12.png)
![s4](img/10.png)
