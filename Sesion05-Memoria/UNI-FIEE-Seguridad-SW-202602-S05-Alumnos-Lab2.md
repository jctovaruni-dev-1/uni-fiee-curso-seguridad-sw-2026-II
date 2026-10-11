# 🧪 Laboratorio 2: Asignación Dinámica en el Heap, Fugas de Memoria y Use-After-Free (UAF)

* **Duración sugerida:** 1 hora y 30 minutos.
* **Entorno:** Google Colab (Linux Ubuntu x86_64).

* **Objetivos de Aprendizaje:**
1. Comprender la arquitectura física y el comportamiento de crecimiento dinámico de la memoria *Heap*.
2. Detectar y evaluar el impacto de las **fugas de memoria (*Memory Leaks*)** mediante herramientas de análisis dinámico.
3. Inducir y analizar la vulnerabilidad de **Uso Tras Liberación (*Use-After-Free* - CWE-416)** producida por punteros colgados (*Dangling Pointers*).
4. Aplicar patrones de refactorización para la gestión segura del ciclo de vida de punteros en C/C++.

---

## 🛠️ PASO 0: Preparación del Entorno en Colab e Instalación de Valgrind

Google Colab incluye el compilador `gcc` por defecto, pero requiere la instalación de la suite de depuración dinámica **Valgrind**.

Ejecuta en una celda de Colab:

```bash
# Paso 0: Actualizar e instalar la herramienta de análisis dinámico de memoria (Valgrind)
!apt-get update -qq
!apt-get install -y -qq valgrind
!valgrind --version

```
* **Explicación Técnica:** **Valgrind** (específicamente su herramienta integrada `memcheck`) simula la ejecución del programa sobre un procesador sintético virtual. Intercepta todas las llamadas del sistema de asignación de memoria (`malloc`, `calloc`, `realloc`, `free`), rastreando bit a bit los bloques inicializados, liberados o huérfanos.


---

## 💻 PASO 1: Creación del Código Fuente Vulnerable (Fugas de Memoria y UAF)

Crearemos un archivo en C llamado `heap_demo.c` que implementa dos funciones de prueba: una que pierde bloques de memoria sin liberar (*Memory Leak*) y otra que invoca un objeto en el *Heap* tras haber sido liberado (*Use-After-Free*).

Ejecuta la siguiente celda:

```python
%%writefile heap_demo.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int id;
    char rol[16];
    void (*mostrar_credencial)(void);
} SesionUsuario;

void funcion_anonima() {
    printf("[!] ACCESO CONCEDIDO: Ejecutando metodo de sesion activa.\n");
}

void funcion_fuga_memoria() {
    printf("\n--- 1. Ejecutando Simulacion de Memory Leak ---\n");
    // Asignación dinámica de 1024 bytes en el Heap
    char *buffer_huérfano = (char*) malloc(1024);
    if (buffer_huérfano == NULL) return;

    strcpy(buffer_huérfano, "Datos persistentes que nunca seran liberados.");
    printf("[+] Memoria asignada en la direccion del Heap: %p\n", (void*)buffer_huérfano);
    
    // ERROR: La función finaliza sin ejecutar free(buffer_huérfano)
    // El puntero local desaparece de la Pila (Stack), pero el bloque sigue ocupado en el Heap.
}

void funcion_use_after_free() {
    printf("\n--- 2. Ejecutando Simulacion de Use-After-Free (UAF) ---\n");
    
    // Asignar objeto de sesión en el Heap
    SesionUsuario *usuario = (SesionUsuario*) malloc(sizeof(SesionUsuario));
    usuario->id = 1001;
    strcpy(usuario->rol, "invitado");
    usuario->mostrar_credencial = funcion_anonima;

    printf("[+] Objeto 'usuario' asignado en: %p\n", (void*)usuario);
    printf("[+] ID: %d | Rol: %s\n", usuario->id, usuario->rol);

    // Liberación del bloque de memoria
    printf("[*] Liberando memoria del objeto 'usuario'...\n");
    free(usuario); 
    
    // VULNERABILIDAD (CWE-416): El puntero 'usuario' NO se asignó a NULL.
    // Sigue apuntando a la dirección liberada (Dangling Pointer).
    printf("[!] ADVERTENCIA: Accediendo a 'usuario' despues del free()...\n");
    printf("[!] ID recuperado (UAF Read): %d\n", usuario->id);
    
    if (usuario->mostrar_credencial != NULL) {
        usuario->mostrar_credencial(); // Invocar puntero a función liberado
    }
}

int main() {
    printf("=== LABORATORIO 2: GESTIÓN DE MEMORIA EN EL HEAP ===\n");
    funcion_fuga_memoria();
    funcion_use_after_free();
    return 0;
}

```

* **Explicación del Código:**
* **Fuga de Memoria (*Memory Leak*):** Se reserva espacio dinámico con `malloc()`, pero la referencia local desaparece al salir de la función. La memoria queda marcada como ocupada permanentemente en el *Heap* hasta que el proceso muere.


* **Use-After-Free (UAF - CWE-416):** La instrucción `free(usuario)` devuelve la página de memoria al gestor del sistema, pero la variable `usuario` conserva la dirección hexadecimal física (*Puntero Colgado*). Acceder o ejecutar datos a través de esta referencia destruida permite leer información residual o desviarla si un objeto malicioso ocupa esa misma porción de memoria posteriormente.

---

## ⚙️ PASO 2: Compilación con Símbolos de Depuración

Compilamos el binario habilitando la bandera `-g` para mapear las líneas exactas del código fuente C dentro del reporte de auditoría.

```bash
# Compilar el programa dinámico
!gcc -g heap_demo.c -o binario_heap
!ls -lh binario_heap

```

---

## 🔬 PASO 3: Auditoría Dinámica de Fugas de Memoria con Valgrind

Ejecutamos el análisis dinámico completo configurando las banderas de rastreo detallado de `valgrind`:

```bash
# Auditoría de leaks y accesos no válidos
!valgrind --leak-check=full \
          --show-leak-kinds=all \
          --track-origins=yes \
          ./binario_heap

```

* **Explicación del Reporte Forense (Resultado Esperado):**
1. **En la función `funcion_use_after_free`:** Valgrind generará la alerta `Invalid read of size 4` o `Invalid read of size 8` en la línea del `printf` y de la llamada a la función. Indicará explícitamente: *Address 0x... is 0 bytes inside a block of size 32 free'd*.
2. **En la función `funcion_fuga_memoria`:** En el resumen final (*LEAK SUMMARY*), Valgrind reportará: `definitely lost: 1,024 bytes in 1 blocks`. Mostrará la traza exacta indicando que los bytes fueron creados por `malloc` en `heap_demo.c`.


---

## 🛡️ PASO 4: Remediation (Refactorización y Hardening del Código)

La refactorización segura para la gestión de memoria dinámica en C requiere:

1. Garantizar la liberación explícita de todo bloque asignado con `malloc` (`free`).
2. **Neutralización del Puntero Colgado:** Asignar inmediatamente la referencia a `NULL` tras la liberación (`free(p); p = NULL;`).
3. Validar que las referencias no sean nulas antes de cualquier lectura o desreferenciación.

Crea el archivo corregido `heap_seguro.c`:

```python
%%writefile heap_seguro.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int id;
    char rol[16];
    void (*mostrar_credencial)(void);
} SesionUsuario;

void funcion_anonima() {
    printf("[!] ACCESO CONCEDIDO: Ejecutando metodo de sesion activa.\n");
}

void funcion_fuga_corregida() {
    printf("\n--- 1. Ejecutando Version Corregida (No Leaks) ---\n");
    char *buffer = (char*) malloc(1024);
    if (buffer == NULL) return;

    strcpy(buffer, "Datos procesados de forma segura.");
    printf("[+] Memoria procesada en: %p\n", (void*)buffer);
    
    // REPARACIÓN: Liberación explícita del recurso asignado
    free(buffer);
    buffer = NULL; // Evita el puntero colgado
    printf("[+] Memoria liberada correctamente.\n");
}

void funcion_uaf_corregida() {
    printf("\n--- 2. Ejecutando Version Corregida (No UAF) ---\n");
    
    SesionUsuario *usuario = (SesionUsuario*) malloc(sizeof(SesionUsuario));
    if (usuario == NULL) return;

    usuario->id = 1001;
    strcpy(usuario->rol, "invitado");
    usuario->mostrar_credencial = funcion_anonima;

    // Liberación y saneamiento del puntero
    free(usuario);
    usuario = NULL; // REPARACIÓN CRÍTICA (Safe Pointer Handling)

    printf("[*] Intentando acceder a la sesion tras liberacion segura...\n");
    
    // Validación contra punteros nulos
    if (usuario != NULL) {
        printf("ID: %d\n", usuario->id);
    } else {
        printf("[✅ CONTROL DE SEGURIDAD]: Se evito el acceso Use-After-Free. El puntero es NULL.\n");
    }
}

int main() {
    printf("=== REMEDIACIÓN DE CÓDIGO EN HEAP ===\n");
    funcion_fuga_corregida();
    funcion_uaf_corregida();
    return 0;
}

```

Recompila y ejecuta la validación con Valgrind:

```bash
# Recompilamos la versión segura
!gcc -g heap_seguro.c -o binario_seguro

# Verificación con Valgrind
!valgrind --leak-check=full ./binario_seguro

```

* **Resultado Esperado:**
* `ERROR SUMMARY: 0 errors from 0 contexts`.
* `All heap blocks were freed -- no leaks are possible`.


---

## 📊 RESUMEN COMPARATIVO DE RESULTADOS

| Escenario | Condición del Heap / Puntero | Resultado Telemetría Valgrind | Severidad / CWE |
| --- | --- | --- | --- |
| **Código Vulnerable** | Punteros colgados (*Dangling*) y bloques no liberados.
 | Alertas `Invalid read` y `definitely lost bytes`.
 | **Alta** / CWE-416 (*UAF*) y CWE-401 (*Memory Leak*).
 |
| **Código Refactorizado** | Liberación explícita y asignación a `NULL`.
 | `0 errors`, `All heap blocks were freed`.
 | **Mitigado / Residuo Cero**.
 |

---

### 💡 Actividad Extra Opcional

1. Modificar `heap_demo.c` e intentar realizar un `free(usuario)` dos veces seguidas (**Double Free - CWE-415**) y observar cómo Valgrind detecta la corrupción de los metadatos del asignador del *Heap*.
2. Discutir cómo abstracciones modernas como los *Smart Pointers* (`std::unique_ptr` / `std::shared_ptr`) en C++ o el sistema de *Ownership/Borrowing* en Rust previenen este tipo de errores desde la etapa de compilación.