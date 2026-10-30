# 📺 Control Remoto TV

Control remoto para Android TV por WiFi, con estilo oscuro de botones en relieve.

## Incluye
- Flechas direccionales con OK (se repiten al mantener pulsado)
- Volumen deslizable y Mute
- Atrás, Inicio, Menú, Entrada y Encendido
- Reproducción (play/pausa, stop, adelantar, retroceder) y canal +/-
- Teclado para escribir en la TV
- Atajos a YouTube, Netflix, Prime y Disney+

## Estructura
```
www/index.html                  Interfaz completa
capacitor.config.json           Configuración de la app
package.json                    Dependencias
.github/workflows/build-apk.yml Compila el APK en GitHub
```

## Obtener el APK
1. Sube todos estos archivos a un repositorio de GitHub (rama `main`).
2. Ve a la pestaña **Actions** → **Construir APK** (se ejecuta solo al subir cambios, o con *Run workflow*).
3. Cuando termine, entra a la ejecución y descarga **control-remoto-tv-apk** en *Artifacts*.
4. Descomprime e instala `app-debug.apk` en tu teléfono.

## Estado
- ✅ Interfaz lista
- ⏳ Conexión real con la TV (protocolo Android TV Remote v2: emparejamiento por código y envío de teclas). Por ahora la app funciona en modo demo.

La interfaz llama a un puente `window.AndroidTV` con `sendKey`, `sendText` y `openApp`; ahí se conectará el plugin nativo.
