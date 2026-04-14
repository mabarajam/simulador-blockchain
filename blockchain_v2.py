"""
Simulador de Blockchain v3 - Estilo Bitcoin
============================================
Features:
- Modelo UTXO (outputs de transacción no gastados)
- Árbol de Merkle para verificación de transacciones
- Wallets determinísticas desde seed phrases
- Inputs/outputs de transacción (como Bitcoin real)
- Headers de bloque separados de datos de transacción
"""

import hashlib
import json
import time
import random
from typing import Optional
from ecdsa import SigningKey, VerifyingKey, SECP256k1

# Terminal colors
class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    RESET = "\033[0m"
    BOLD = "\033[1m"

def color(text, c):
    return f"{c}{text}{Colors.RESET}"

# Simple deterministic word list for seed generation (subset of BIP39)
WORD_LIST = [
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse",
    "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire", "across", "act",
    "action", "actor", "actress", "actual", "adapt", "add", "addict", "address", "adjust", "admit",
    "adult", "advance", "advice", "aerial", "affair", "afford", "afraid", "again", "age", "agent",
    "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album", "alcohol", "alert",
    "alien", "all", "alley", "allow", "almost", "alone", "alpha", "already", "also", "alter",
    "always", "amateur", "amazing", "among", "amount", "amused", "analyst", "anchor", "ancient", "anger",
    "angle", "angry", "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
    "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april", "arch", "arctic",
    "area", "arena", "argue", "arm", "armed", "armor", "army", "around", "arrange", "arrest",
]

def generate_seed_phrase():
    """Generate a random 12-word seed phrase (simplified BIP39 style)."""
    return " ".join(random.sample(WORD_LIST, 12))

def seed_to_private_key(seed_phrase):
    """Convert seed phrase to a private key (deterministic)."""
    seed_hash = hashlib.sha256(seed_phrase.encode()).hexdigest()
    private_key_int = int(seed_hash, 16) % SECP256k1.order
    return SigningKey.from_secret_exponent(private_key_int, curve=SECP256k1)


# --- Wallet ---
class Wallet:
    def __init__(self, seed_phrase=None):
        if seed_phrase:
            self.private_key = seed_to_private_key(seed_phrase)
            self.seed_phrase = seed_phrase
        else:
            self.private_key = SigningKey.generate(curve=SECP256k1)
            self.seed_phrase = None
        self.public_key = self.private_key.get_verifying_key()
        self.address = hashlib.sha256(self.public_key.to_string()).hexdigest()[:20]

    def sign_transaction(self, data):
        return self.private_key.sign(data.encode()).hex()

    @staticmethod
    def verify_signature(public_key, data, signature_hex):
        try:
            return public_key.verify(bytes.fromhex(signature_hex), data.encode())
        except Exception:
            return False

    def __repr__(self):
        return f"Wallet({self.address[:12]}...)"


# --- Transaction Input/Output ---
class TxInput:
    def __init__(self, prev_tx_hash, output_index, signature=""):
        self.prev_tx_hash = prev_tx_hash
        self.output_index = output_index
        self.signature = signature

    def to_dict(self):
        return {
            "prev_tx": self.prev_tx_hash[:16] if self.prev_tx_hash else "genesis",
            "output_index": self.output_index,
            "signature": self.signature[:16] + "..." if self.signature else "",
        }

    def __repr__(self):
        if not self.prev_tx_hash:
            return f"Input(coinbase)"
        return f"Input({self.prev_tx_hash[:8]}...[{self.output_index}])"


class TxOutput:
    def __init__(self, address, amount):
        self.address = address
        self.amount = amount
        self.spent = False

    def to_dict(self):
        return {
            "address": self.address,
            "amount": self.amount,
            "spent": self.spent,
        }

    def __repr__(self):
        status = "GASTADO" if self.spent else "SIN GASTAR"
        return f"Output({self.address[:10]}... | {self.amount} BTC | {status})"


# --- Transaction ---
class Transaction:
    def __init__(self, inputs=None, outputs=None):
        self.inputs = inputs or []
        self.outputs = outputs or []
        self.timestamp = time.time()

    def calculate_hash(self):
        tx_data = json.dumps({
            "inputs": [i.to_dict() for i in self.inputs],
            "outputs": [o.to_dict() for o in self.outputs],
            "timestamp": self.timestamp,
        }, sort_keys=True)
        return hashlib.sha256(tx_data.encode()).hexdigest()

    def sign(self, wallet):
        tx_hash = self.calculate_hash()
        for inp in self.inputs:
            inp.signature = wallet.sign_transaction(tx_hash)

    def verify(self, public_key):
        tx_hash = self.calculate_hash()
        for inp in self.inputs:
            if inp.signature and not Wallet.verify_signature(public_key, tx_hash, inp.signature):
                return False
        return True

    def is_coinbase(self):
        return len(self.inputs) == 0 or all(i.prev_tx_hash == "" for i in self.inputs)

    def to_dict(self):
        return {
            "hash": self.calculate_hash(),
            "inputs": [i.to_dict() for i in self.inputs],
            "outputs": [o.to_dict() for o in self.outputs],
            "timestamp": self.timestamp,
        }

    def __repr__(self):
        total_out = sum(o.amount for o in self.outputs)
        if self.is_coinbase():
            return f"TX(coinbase -> {self.outputs[0].address[:8]}... | {self.outputs[0].amount} BTC)"
        return f"TX({len(self.inputs)} inputs -> {len(self.outputs)} outputs | {total_out} BTC)"


# --- Merkle Tree ---
def compute_merkle_root(tx_hashes):
    if not tx_hashes:
        return "0" * 64
    if len(tx_hashes) == 1:
        return tx_hashes[0]

    leaves = [hashlib.sha256(h.encode()).hexdigest() for h in tx_hashes]

    while len(leaves) > 1:
        if len(leaves) % 2 == 1:
            leaves.append(leaves[-1])
        next_level = []
        for i in range(0, len(leaves), 2):
            combined = leaves[i] + leaves[i + 1]
            next_level.append(hashlib.sha256(combined.encode()).hexdigest())
        leaves = next_level

    return leaves[0]


# --- Block Header ---
class BlockHeader:
    def __init__(self, version, previous_hash, merkle_root, timestamp, difficulty, nonce=0):
        self.version = version
        self.previous_hash = previous_hash
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.difficulty = difficulty
        self.nonce = nonce

    def calculate_hash(self):
        header_string = json.dumps({
            "version": self.version,
            "previous_hash": self.previous_hash,
            "merkle_root": self.merkle_root,
            "timestamp": self.timestamp,
            "difficulty": self.difficulty,
            "nonce": self.nonce,
        }, sort_keys=True)
        return hashlib.sha256(header_string.encode()).hexdigest()


# --- Block ---
class Block:
    def __init__(self, index, timestamp, transactions, previous_hash, difficulty):
        self.index = index
        self.previous_hash = previous_hash
        self.transactions = transactions
        self.difficulty = difficulty

        tx_hashes = [tx.calculate_hash() for tx in transactions]
        self.merkle_root = compute_merkle_root(tx_hashes)

        self.header = BlockHeader(
            version=1,
            previous_hash=previous_hash,
            merkle_root=self.merkle_root,
            timestamp=timestamp,
            difficulty=difficulty,
            nonce=0,
        )
        self.hash = self.header.calculate_hash()

    def mine_block(self):
        target = "0" * self.difficulty
        attempts = 0
        while self.hash[:self.difficulty] != target:
            self.header.nonce += 1
            self.hash = self.header.calculate_hash()
            attempts += 1
        print(f"  {color('¡Minado!', Colors.GREEN)} Hash: {self.hash[:20]}... (nonce: {self.header.nonce}, intentos: {attempts})")

    def __repr__(self):
        return f"Block(#{self.index}, {self.hash[:10]}..., {len(self.transactions)} txs, merkle={self.merkle_root[:8]}...)"


# --- Node ---
class Node:
    def __init__(self, node_id, difficulty=2):
        self.node_id = node_id
        self.difficulty = difficulty
        self.chain = []
        self.pending_transactions = []
        self.base_reward = 50
        self.halving_interval = 5
        self.utxo_set = {}
        self.create_genesis_block()

    def get_current_reward(self):
        halvings = len(self.chain) // self.halving_interval
        if halvings >= 30:
            return 0
        return self.base_reward / (2 ** halvings)

    def find_utxos(self, address):
        utxos = []
        for tx_hash, outputs in self.utxo_set.items():
            for idx, output in outputs.items():
                if not output.spent and output.address == address:
                    utxos.append((tx_hash, idx, output))
        return utxos

    def get_balance(self, address):
        utxos = self.find_utxos(address)
        return round(sum(output.amount for _, _, output in utxos), 3)

    def create_genesis_block(self):
        coinbase = Transaction(
            inputs=[TxInput("", 0)],
            outputs=[TxOutput("genesis", 0)]
        )
        genesis = Block(0, time.time(), [coinbase], "0" * 64, self.difficulty)
        genesis.mine_block()
        self.chain.append(genesis)
        self._update_utxos(coinbase.calculate_hash(), coinbase.outputs)

    def _update_utxos(self, tx_hash, outputs):
        self.utxo_set[tx_hash] = {}
        for idx, output in enumerate(outputs):
            self.utxo_set[tx_hash][idx] = output

    def _mark_utxos_spent(self, tx):
        for inp in tx.inputs:
            if inp.prev_tx_hash in self.utxo_set:
                if inp.output_index in self.utxo_set[inp.prev_tx_hash]:
                    self.utxo_set[inp.prev_tx_hash][inp.output_index].spent = True

    def create_transaction(self, sender_wallet, receiver_address, amount):
        utxos = self.find_utxos(sender_wallet.address)
        if not utxos:
            print(f"  {color('Rechazado:', Colors.RED)} No hay outputs sin gastar para esta dirección")
            return None

        total = 0
        selected = []
        for tx_hash, idx, output in utxos:
            selected.append((tx_hash, idx, output))
            total += output.amount
            if total >= amount + 0.001:
                break

        if total < amount + 0.001:
            print(f"  {color('Rechazado:', Colors.RED)} Fondos insuficientes (tiene {total}, necesita {amount + 0.001})")
            return None

        inputs = [TxInput(tx_hash, idx) for tx_hash, idx, _ in selected]
        outputs = [TxOutput(receiver_address, amount)]

        change = total - amount - 0.001
        if change > 0:
            outputs.append(TxOutput(sender_wallet.address, round(change, 3)))

        tx = Transaction(inputs, outputs)
        tx.sign(sender_wallet)
        return tx

    def add_transaction(self, tx, sender_wallet=None):
        if not tx.is_coinbase():
            for inp in tx.inputs:
                if inp.prev_tx_hash not in self.utxo_set:
                    print(f"  {color('Rechazado:', Colors.RED)} Input inválido: transacción desconocida {inp.prev_tx_hash[:8]}...")
                    return False
                if inp.output_index not in self.utxo_set[inp.prev_tx_hash]:
                    print(f"  {color('Rechazado:', Colors.RED)} Input inválido: el output {inp.output_index} no existe")
                    return False
                if self.utxo_set[inp.prev_tx_hash][inp.output_index].spent:
                    print(f"  {color('Rechazado:', Colors.RED)} ¡Intento de doble gasto!")
                    return False

            if sender_wallet:
                if not tx.verify(sender_wallet.public_key):
                    print(f"  {color('Rechazado:', Colors.RED)} ¡Firma inválida!")
                    return False

        self.pending_transactions.append(tx)
        print(f"  {color('Agregado al mempool:', Colors.YELLOW)} {tx}")
        return True

    def mine_pending_transactions(self, miner_address):
        reward = self.get_current_reward()

        coinbase = Transaction(
            inputs=[TxInput("", 0)],
            outputs=[TxOutput(miner_address, reward)]
        )

        txs = [coinbase] + self.pending_transactions.copy()

        new_block = Block(len(self.chain), time.time(), txs, self.chain[-1].hash, self.difficulty)
        print(f"\n{color('Minando bloque...', Colors.CYAN)} (Recompensa: {reward} BTC, Merkle: {new_block.merkle_root[:16]}...)")
        new_block.mine_block()
        self.chain.append(new_block)

        for tx in txs:
            tx_hash = tx.calculate_hash()
            self._mark_utxos_spent(tx)
            self._update_utxos(tx_hash, tx.outputs)

        self.pending_transactions = []
        print(f"  {color('¡Bloque agregado!', Colors.GREEN)} Total: {len(self.chain)}")

    def mine_solo_block(self, miner_address):
        reward = self.get_current_reward()
        coinbase = Transaction(
            inputs=[TxInput("", 0)],
            outputs=[TxOutput(miner_address, reward)]
        )
        new_block = Block(len(self.chain), time.time(), [coinbase], self.chain[-1].hash, self.difficulty)

        print(f"\n{color('Minando solo...', Colors.CYAN)} (Recompensa: {reward} BTC)")
        new_block.mine_block()
        self.chain.append(new_block)

        tx_hash = coinbase.calculate_hash()
        self._update_utxos(tx_hash, coinbase.outputs)

        print(f"  {color('¡Bloque agregado!', Colors.GREEN)} Total: {len(self.chain)}")

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]
            if current.hash[:self.difficulty] != "0" * self.difficulty:
                return False
            if current.header.previous_hash != previous.hash:
                return False
            if current.hash != current.header.calculate_hash():
                return False
            tx_hashes = [tx.calculate_hash() for tx in current.transactions]
            expected_merkle = compute_merkle_root(tx_hashes)
            if current.merkle_root != expected_merkle:
                return False
        return True

    def display_chain(self):
        print(f"\n{color('='*60, Colors.WHITE)}")
        print(f"{color(f'  ESTADO DE LA CADENA (Nodo: {self.node_id})', Colors.HEADER)}")
        print(f"{color('='*60, Colors.WHITE)}")
        print(f"  Bloques: {len(self.chain)} | TXs pendientes: {len(self.pending_transactions)}")
        print(f"  UTXOs: {sum(len(v) for v in self.utxo_set.values())} outputs rastreados")
        print(f"  Válida: {color('SÍ', Colors.GREEN) if self.is_chain_valid() else color('NO', Colors.RED)}")
        print()
        for block in self.chain:
            print(f"  Bloque #{block.index} | Hash: {block.hash[:16]}... | TXs: {len(block.transactions)}")
            print(f"    Merkle Root: {block.merkle_root[:32]}...")
            for tx in block.transactions:
                print(f"    {tx}")
                if tx.is_coinbase():
                    print(f"      [COINBASE] Recompensa -> {tx.outputs[0].address[:10]}... | {tx.outputs[0].amount} BTC")
                else:
                    for inp in tx.inputs:
                        print(f"      Input: {inp}")
                    for out in tx.outputs:
                        print(f"      Output: {out}")
            print()

    def sync_with_node(self, other_node):
        if self.node_id == other_node.node_id:
            return False
        if len(other_node.chain) > len(self.chain) and other_node.is_chain_valid():
            print(f"\n  {color('Sincronizando...', Colors.CYAN)} {other_node.node_id} tiene cadena más larga ({len(other_node.chain)} > {len(self.chain)})")
            self.chain = other_node.chain.copy()
            self.pending_transactions = []
            self.utxo_set = other_node.utxo_set.copy()
            print(f"  {color('¡Sincronizado!', Colors.GREEN)} Ahora en {len(self.chain)} bloques")
            return True
        return False


# --- Menú ---
def print_menu():
    print(f"\n{color('='*50, Colors.HEADER)}")
    print(f"{color('  SIMULADOR DE BLOCKCHAIN', Colors.HEADER)}")
    print(f"{color('='*50, Colors.HEADER)}")
    print(f"  1. Crear Wallet")
    print(f"  2. Listar Wallets")
    print(f"  3. Enviar Transacción")
    print(f"  4. Minar Transacciones Pendientes")
    print(f"  5. Ver Cadena")
    print(f"  6. Ver Balance")
    print(f"  7. Ver Todos los Balances")
    print(f"  8. Minar Solo (ganar BTC)")
    print(f"  9. Sincronizar Nodos")
    print(f"  10. Demo Completa")
    print(f"  11. Prueba de Manipulación")
    print(f"  q. Salir")
    print(f"{color('='*50, Colors.HEADER)}")

def run_demo(wallets, node):
    print(f"\n{color('Ejecutando demo completa...', Colors.CYAN)}")

    demo_wallets = {"Alice": Wallet(), "Bob": Wallet(), "Charlie": Wallet()}
    wallets.update(demo_wallets)
    print(f"\n{color('Wallets de demo creadas:', Colors.GREEN)}")
    for name, w in demo_wallets.items():
        print(f"  {name}: {w.address[:20]}...")

    node.mine_solo_block(demo_wallets["Alice"].address)

    alice = demo_wallets["Alice"]
    bob = demo_wallets["Bob"]
    charlie = demo_wallets["Charlie"]

    tx1 = node.create_transaction(alice, bob.address, 10)
    if tx1:
        node.add_transaction(tx1, alice)

    tx2 = node.create_transaction(bob, charlie.address, 5)
    if tx2:
        node.add_transaction(tx2, bob)

    node.mine_pending_transactions(alice.address)
    node.display_chain()

    print(f"\n{color('BALANCES:', Colors.HEADER)}")
    for name, w in demo_wallets.items():
        print(f"  {name}: {node.get_balance(w.address)} BTC ({len(node.find_utxos(w.address))} UTXOs)")

    print(f"\n{color('PRUEBA DE MANIPULACIÓN:', Colors.RED)}")
    if len(node.chain) > 1:
        node.chain[1].header.nonce = 0
        node.chain[1].hash = node.chain[1].header.calculate_hash()
        valid = node.is_chain_valid()
        result = "NO - ¡Detectado!" if not valid else "SÍ (¡BUG!)"
        print(f"  ¿Cadena válida después de manipular? {color(result, Colors.GREEN if not valid else Colors.RED)}")

def main():
    print(f"\n{color('¡Bienvenido al Simulador de Blockchain!', Colors.HEADER)}")
    print(f"{color('Modelo UTXO, árboles de Merkle, seed phrases, transacciones firmadas', Colors.CYAN)}")

    wallets = {}
    nodes = [Node("Nodo-1", difficulty=2)]
    main_node = nodes[0]
    miner_address = None

    while True:
        print_menu()
        choice = input(f"\n  {color('Elige:', Colors.YELLOW)} ").strip().lower()

        if choice == "q":
            print(f"  {color('¡Hasta luego!', Colors.GREEN)}")
            break

        elif choice == "1":
            print(f"\n  {color('Crear Wallet:', Colors.HEADER)}")
            method = input(f"  ¿Generar aleatoria o desde seed phrase? (r/s): ").strip().lower()
            if method == "s":
                seed = input(f"  Ingresa 12 palabras (separadas por espacio): ").strip()
                wallet = Wallet(seed)
                print(f"  {color('Restaurada desde seed:', Colors.GREEN)}")
            else:
                wallet = Wallet()
                seed = generate_seed_phrase()
                wallet.seed_phrase = seed
                print(f"  {color('¡Nueva wallet creada!', Colors.GREEN)}")
                print(f"  {color('Seed phrase:', Colors.YELLOW)} {seed}")
                print(f"  {color('IMPORTANTE: ¡Guarda esta frase!', Colors.RED)} Cualquiera con ella puede restaurar tu wallet.")

            name = input(f"  Nombre de wallet (ej. Alice): ").strip() or f"Wallet-{len(wallets)+1}"
            if name in wallets:
                print(f"  {color('¡Esa wallet ya existe!', Colors.RED)}")
                continue
            wallets[name] = wallet
            print(f"  {color('Creada:', Colors.GREEN)} {name}")
            print(f"  Dirección: {wallet.address[:30]}...")

        elif choice == "2":
            if not wallets:
                print(f"  {color('No hay wallets aún.', Colors.RED)}")
            else:
                print(f"\n  {color('Tus Wallets:', Colors.GREEN)}")
                for name, w in wallets.items():
                    bal = main_node.get_balance(w.address)
                    utxos = main_node.find_utxos(w.address)
                    print(f"    {name}: {w.address[:30]}...")
                    print(f"      Balance: {bal} BTC ({len(utxos)} UTXOs)")
                    if w.seed_phrase:
                        print(f"      Seed: {w.seed_phrase[:30]}...")

        elif choice == "3":
            if not wallets:
                print(f"  {color('¡Crea una wallet primero!', Colors.RED)}")
                continue
            sender_name = input(f"  Desde (nombre de wallet): ").strip()
            receiver_name = input(f"  Hacia (nombre de wallet): ").strip()
            if sender_name not in wallets or receiver_name not in wallets:
                print(f"  {color('¡Wallet no encontrada!', Colors.RED)}")
                continue
            if sender_name == receiver_name:
                print(f"  {color('¡No puedes enviarte a ti mismo!', Colors.RED)}")
                continue
            try:
                amount = float(input(f"  Monto (BTC): ").strip())
            except ValueError:
                print(f"  {color('¡Monto inválido!', Colors.RED)}")
                continue
            if amount <= 0:
                print(f"  {color('¡El monto debe ser positivo!', Colors.RED)}")
                continue

            sender = wallets[sender_name]
            receiver = wallets[receiver_name]
            tx = main_node.create_transaction(sender, receiver.address, amount)
            if tx:
                main_node.add_transaction(tx, sender)

        elif choice == "4":
            if not wallets:
                print(f"  {color('¡Crea una wallet primero!', Colors.RED)}")
                continue
            print(f"\n  {color('Wallets disponibles:', Colors.HEADER)}")
            for i, name in enumerate(wallets, 1):
                print(f"    {i}. {name} ({wallets[name].address[:20]}...)")
            pick = input(f"  ¿A qué wallet minar? (número o nombre): ").strip()
            if pick.isdigit():
                idx = int(pick) - 1
                if 0 <= idx < len(wallets):
                    miner_name = list(wallets.keys())[idx]
                    miner_address = wallets[miner_name].address
                else:
                    print(f"  {color('¡Selección inválida!', Colors.RED)}")
                    continue
            elif pick in wallets:
                miner_address = wallets[pick].address
            else:
                print(f"  {color('¡Wallet no encontrada!', Colors.RED)}")
                continue
            main_node.mine_pending_transactions(miner_address)

        elif choice == "5":
            main_node.display_chain()

        elif choice == "6":
            name = input(f"  Nombre de wallet: ").strip()
            if name not in wallets:
                print(f"  {color('¡Wallet no encontrada!', Colors.RED)}")
                continue
            addr = wallets[name].address
            bal = main_node.get_balance(addr)
            utxos = main_node.find_utxos(addr)
            print(f"  {name} ({addr[:20]}...): {color(bal, Colors.GREEN)} BTC")
            print(f"  UTXOs: {len(utxos)}")
            for tx_hash, idx, output in utxos:
                print(f"    {tx_hash[:12]}...[{idx}] = {output.amount} BTC")

        elif choice == "7":
            if not wallets:
                print(f"  {color('No hay wallets para verificar.', Colors.RED)}")
                continue
            print(f"\n  {color('TODOS LOS BALANCES:', Colors.HEADER)}")
            for name, w in wallets.items():
                bal = main_node.get_balance(w.address)
                utxos = main_node.find_utxos(w.address)
                c = Colors.GREEN if bal >= 0 else Colors.RED
                print(f"    {name}: {color(bal, c)} BTC ({len(utxos)} UTXOs)")

        elif choice == "8":
            if not wallets:
                print(f"  {color('¡Crea una wallet primero!', Colors.RED)}")
                continue
            print(f"\n  {color('Wallets disponibles:', Colors.HEADER)}")
            for i, name in enumerate(wallets, 1):
                print(f"    {i}. {name} ({wallets[name].address[:20]}...)")
            pick = input(f"  ¿A qué wallet minar? (número o nombre): ").strip()
            if pick.isdigit():
                idx = int(pick) - 1
                if 0 <= idx < len(wallets):
                    miner_name = list(wallets.keys())[idx]
                    miner_address = wallets[miner_name].address
                else:
                    print(f"  {color('¡Selección inválida!', Colors.RED)}")
                    continue
            elif pick in wallets:
                miner_address = wallets[pick].address
            else:
                print(f"  {color('¡Wallet no encontrada!', Colors.RED)}")
                continue
            main_node.mine_solo_block(miner_address)

        elif choice == "9":
            if len(nodes) < 2:
                nodes.append(Node(f"Nodo-{len(nodes)+1}"))
                print(f"  {color('Creado:', Colors.GREEN)} {nodes[-1].node_id}")
            print(f"\n  {color('Estado de Nodos:', Colors.HEADER)}")
            for n in nodes:
                print(f"    {n.node_id}: {len(n.chain)} bloques")
            for n in nodes[1:]:
                n.sync_with_node(main_node)
            print(f"\n  {color('¡Sincronización completa!', Colors.GREEN)}")

        elif choice == "10":
            run_demo(wallets, main_node)

        elif choice == "11":
            print(f"\n{color('Manipulando Bloque #1...', Colors.RED)}")
            if len(main_node.chain) > 1:
                main_node.chain[1].header.nonce = 0
                main_node.chain[1].hash = main_node.chain[1].header.calculate_hash()
                valid = main_node.is_chain_valid()
                result = "NO - ¡Detectado!" if not valid else "SÍ (¡BUG!)"
                print(f"  ¿Cadena válida? {color(result, Colors.GREEN if not valid else Colors.RED)}")
            else:
                print(f"  {color('¡Mina algunos bloques primero!', Colors.RED)}")

        else:
            print(f"  {color('Opción inválida.', Colors.RED)}")

if __name__ == "__main__":
    main()
