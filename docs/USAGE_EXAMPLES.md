# 📖 Ejemplos de Uso — HashCracker GUI v1.2.0

---

## Ejemplo 1: Hash MD5 directo con Smart Attack

1. Abre la app: `python main.py`
2. 📂 → selecciona `hashcat.exe`
3. En "Hash objetivo", pega: `5f4dcc3b5aa765d61d8327deb882cf99`
4. Clic en **🔍 Detectar** → "MD5 (modo 0)"
5. Modo de ataque: **🧠 Smart (inteligente)**
6. ▶ **INICIAR**
7. Resultado: `password` en la etapa "🔤 Minúsculas puras"

---

## Ejemplo 2: Archivo con 200 hashes

1. Clic en **📄 Desde archivo** → selecciona `test_hash.txt`
2. Se muestra "200 hashes" y se activa el checkbox múltiple
3. **🔍 Detectar** → "MD5 (modo 0)"
4. **🧠 Smart** → ▶ **INICIAR**
5. La consola muestra cracks en tiempo real: `🔓 CRACK: hash:password`
6. La barra inferior muestra progreso: `45/200 crackeados`
7. La cadena continúa por todas las etapas necesarias
8. Al terminar → auto-save en `Result/2026-10-23_22-05-54/`

---

## Ejemplo 3: SQL Dump con emails (email:hash)

1. Clic en **📄 Desde archivo** → selecciona `test_sqldump.txt`
2. Auto-detecta formato email:hash → activa checkbox 📧
3. Consola muestra: "Dump parseado: 200 registros (email:hash)"
4. **🔍 Detectar** → "MD5 (modo 0)"
5. **🧠 Smart** → ▶ **INICIAR**
6. Consola muestra en vivo:
   ```
   🔓 CRACK: e99a18c428cb38d5f260853678922e03:abc123
       📧 carlos.lopez@gmail.com → abc123
   🔓 CRACK: b5c0b187fe309af0f4d35982fd961d7e:love
       📧 maria.garcia@hotmail.com → love
   ```
7. Al terminar → `Result/<timestamp>/cracked.txt` contiene:
   ```
   carlos.lopez@gmail.com:abc123
   maria.garcia@hotmail.com:love
   juan.martinez@yahoo.com:dragon
   ...
   ```

---

## Ejemplo 4: NTLM con máscara manual

1. Hash: `32ed87bdb5fdc5e9cba88547376818d4`
2. Detectar → NTLM (modo 1000) *(o cambiar modo manual a 1000)*
3. Modo ataque: `3 — Fuerza bruta / Mask`
4. ❓ → ver referencia de máscaras
5. Máscara: `?u?l?l?l?l?d?d?d`
6. ▶ **INICIAR**

---

## Ejemplo 5: WPA2 con diccionario

1. **📄 Desde archivo** → selecciona `.hc22000`
2. Detectar → WPA-PBKDF2-PMKID+EAPOL (modo 22000)
3. Modo: `0 — Diccionario`
4. 📂 Wordlist → `rockyou.txt`
5. ▶ **INICIAR**

---

## Ejemplo 6: Historial y export

1. Después de varias ejecuciones, clic en **📋 Historial**
2. Tabla con todos los cracks: email/hash, password, algoritmo, fecha
3. Clic en **💾 Exportar**:
   - `.txt` → `email:password` (dump) o `hash:password`
   - `.csv` → tabla completa
   - `.json` → datos estructurados

---

## Ejemplo 7: Detener y continuar

1. Durante una ejecución larga, clic en **■ DETENER**
2. El proceso hashcat se mata inmediatamente
3. Los resultados parciales ya están guardados en el historial
4. Para continuar, simplemente vuelve a dar ▶ **INICIAR**

---

## Formatos de archivo soportados

### Hash directo
```
5f4dcc3b5aa765d61d8327deb882cf99
```

### Multi-hash (un hash por línea)
```
5f4dcc3b5aa765d61d8327deb882cf99
098f6bcd4621d373cade4e832627b4f6
1a1dc91c907325c69271ddf0c944bc72
```

### SQL Dump (email:hash)
```
-- Comentarios ignorados
carlos@gmail.com:5f4dcc3b5aa765d61d8327deb882cf99
maria@hotmail.com:098f6bcd4621d373cade4e832627b4f6
```

### CSV con headers
```
email,password_hash,username
carlos@gmail.com,5f4dcc3b5aa765d61d8327deb882cf99,carlos
maria@hotmail.com,098f6bcd4621d373cade4e832627b4f6,maria
```

---

## Tips

- **Sin wordlist**: Smart funciona bien solo con fuerza bruta (54 etapas inteligentes)
- **Con wordlist**: Agrega `rockyou.txt` para crackear passwords de diccionario primero
- **Multi-hash**: hashcat es más eficiente con muchos hashes a la vez
- **SQL dump**: el mapeo email→password se hace automáticamente
- **Resultados**: siempre guardados en `Result/<fecha_hora>/` automáticamente
- **Stop**: seguro en cualquier momento, los cracks parciales ya están guardados
- **Historial**: persiste entre sesiones en `results.json`
- **GPU**: se usa CUDA si está disponible, OpenCL como fallback
