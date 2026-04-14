# Simulador de Blockchain

Un simulador de blockchain estilo Bitcoin en Python. Crea wallets con seed phrases, envía transacciones basadas en UTXO, mina bloques con árboles de Merkle y ve cómo funciona el consenso. Hecho para aprender — no para producción.

## Features

- **Wallets ECDSA** — pares de claves privadas/públicas reales con curva secp256k1 (la misma que Bitcoin)
- **Seed phrases** — generación determinística de wallets (12 palabras, estilo BIP39)
- **Modelo UTXO** — rastrea outputs de transacción no gastados (así es como Bitcoin previene el doble gasto en la realidad)
- **Inputs/outputs de transacción** — estructurados como transacciones reales de Bitcoin
- **Árboles de Merkle** — cada bloque tiene un Merkle root para verificación eficiente de transacciones
- **Headers de bloque** — metadata del header separada de los datos de transacción (como Bitcoin real)
- **Mining proof of work** — mina bloques con dificultad ajustable
- **Halving de recompensa** — la recompensa se reduce a la mitad con el tiempo, como Bitcoin
- **Simulación multi-nodo** — crea múltiples nodos y sincronízalos
- **Detección de manipulación** — modifica un bloque y ve cómo se rompe la cadena

## Cómo ejecutarlo

```bash
pip install -r requirements.txt
python3 blockchain_v2.py
```

## Qué vas a aprender

- Cómo el hashing une los bloques entre sí
- Por qué existe el mining (proof of work)
- Cómo las firmas digitales previenen el fraude
- Cómo funcionan los UTXOs (y por qué Bitcoin los usa en vez de balances de cuenta)
- Qué son los árboles de Merkle y por qué importan
- Cómo las seed phrases generan wallets de forma determinística
- Cómo funciona el consenso entre nodos
- Qué pasa cuando alguien manipula la cadena

## Archivos

| Archivo | Descripción |
|---------|-------------|
| `blockchain_v2.py` | Simulador interactivo principal (v3 con UTXO, Merkle trees, seed phrases) |
| `requirements.txt` | Dependencias de Python |

## Dependencias

- `ecdsa` — para criptografía de curva elíptica

## Licencia

Ninguna — úsalo para aprender, modifícalo como quieras.
