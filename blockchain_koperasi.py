"""Praktikum 1 - Blockchain Permissioned Koperasi (versi perbaikan).

JALANKAN:
    python -m pip install cryptography
    python blockchain_koperasi.py              # presentasi/demo koperasi
    python blockchain_koperasi.py --test       # uji regresi otomatis

PADANAN MODUL:
    class Block; link_block (parent hash); replay_chain (deteksi manipulasi);
    Wallet/Transaction (private-public key, sign-verify).

CAKUPAN: simulasi authority-based dengan 4 validator, kuorum 3 tanda tangan
unik. Setiap validator memeriksa kandidat terhadap salinan chain sendiri.
BUKAN protokol IBFT lengkap: belum ada pesan prepare/commit, round-change,
transport jaringan, atau jaminan BFT produksi. Semua node berjalan dalam satu
proses lokal. Library kriptografi digunakan seperti pada modul praktikum.

ATURAN BISNIS DEMO:
- Nominal integer rupiah, positif; tanpa bunga/denda/biaya transaksi.
- Pencairan menambah saldo simpanan sebesar pokok pinjaman yang disetujui.
- Angsuran adalah pembayaran tunai eksternal: mengurangi sisa utang, tidak
  mendebit saldo simpanan. Setiap pembayaran mengurangi tenor satu periode;
  angsuran periode terakhir harus melunasi sisa utang.
- loan_approval ditambahkan sebagai transaksi agar persetujuan dapat diaudit.
- Genesis kosong ditandatangani 4 validator. Pengesahan block menggunakan
  kuorum tanda tangan validator sesuai desain koperasi.

BATASAN/TARGET TUGAS BESAR: penyimpanan permanen, keystore terenkripsi,
rotasi/pencabutan kunci melalui tata kelola, jaringan antarnode, IBFT lengkap,
UI dan SPV. Whitelist tetap selama satu sesi; seluruh kunci/data di memori.
Salinan observer terpisah dan antarmuka baca mengembalikan deepcopy, tetapi
bukan isolasi keamanan terhadap orang yang menguasai proses Python.
"""

import argparse
import copy
import hashlib
import json
import time
import unittest
import uuid
from dataclasses import dataclass, field

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
except ImportError:
    raise SystemExit('Pasang dependensi: python -m pip install cryptography')

VALIDATOR_NAMES = ('Pengurus Pusat', 'Pengurus Koperasi',
                   'Pengurus Pengawas', 'Otoritas Konsorsium')
QUORUM = 3                         # jumlah total tetap 4, bukan node online
NETWORK = 'koperasi-praktikum-1'
ZERO_HASH = '0' * 64


def canonical(data):
    """Serialisasi deterministik: objek sama menghasilkan byte yang sama."""
    return json.dumps(data, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def digest(data):
    return hashlib.sha256(canonical(data)).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


class Wallet:
    def __init__(self):
        self._private = ec.generate_private_key(ec.SECP256R1())

    @property
    def public_pem(self):
        return self._private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    def sign(self, payload):
        # ECDSA meng-hash payload SATU kali menggunakan SHA-256.
        return self._private.sign(payload, ec.ECDSA(hashes.SHA256())).hex()


def verify(public_pem, signature, payload):
    try:
        public = serialization.load_pem_public_key(public_pem.encode())
        public.verify(bytes.fromhex(signature), payload, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError, AttributeError):
        return False


@dataclass
class Transaction:
    tx_type: str
    member_id: str
    amount: int
    operator_id: str
    extra: dict = field(default_factory=dict)
    timestamp: int = field(default_factory=lambda: int(time.time()))
    tx_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    network: str = NETWORK
    signature: str = ''

    def payload(self):
        return {k: copy.deepcopy(v) for k, v in vars(self).items() if k != 'signature'}

    def sign(self, wallet):
        self.signature = wallet.sign(canonical(self.payload()))
        return self

    def to_dict(self):
        return copy.deepcopy(vars(self))


@dataclass
class State:
    balances: dict = field(default_factory=dict)
    loans: dict = field(default_factory=dict)
    seen: set = field(default_factory=set)


def apply_transaction(tx, state, permission_list):
    """Validasi lalu ubah STATE KERJA saja; tidak menyentuh saldo final.

    Public key wajib berasal dari whitelist, tidak diterima dari pemanggil.
    Dipakai ulang oleh participant, validator, dan auditor saat replay.
    """
    require(isinstance(tx, Transaction), 'Format transaksi salah')
    require(tx.network == NETWORK, 'Network transaksi tidak sesuai')
    require(isinstance(tx.tx_id, str) and len(tx.tx_id) == 32, 'tx_id tidak valid')
    require(tx.tx_id not in state.seen, 'Transaksi duplikat/replay')
    require(isinstance(tx.operator_id, str) and tx.operator_id in permission_list,
            'Operator tidak terdaftar')
    require(verify(permission_list[tx.operator_id], tx.signature, canonical(tx.payload())),
            'Signature tidak valid untuk operator terdaftar')
    require(isinstance(tx.member_id, str) and bool(tx.member_id.strip()), 'ID anggota kosong')
    require(type(tx.amount) is int and tx.amount > 0, 'Nominal harus integer positif')
    require(type(tx.timestamp) is int and tx.timestamp >= 0, 'Timestamp harus integer')
    require(isinstance(tx.extra, dict), 'Extra harus dictionary')
    schemas = {
        'deposit': set(), 'withdrawal': {'saldo_sebelum', 'saldo_sesudah'},
        'loan_request': {'loan_id', 'tenor_bulan', 'status'},
        'loan_approval': {'loan_id'}, 'loan_disbursement': {'loan_id'},
        'installment_payment': {'loan_id', 'sisa_tenor'},
    }
    require(tx.tx_type in schemas, 'Jenis transaksi tidak dikenal')
    require(set(tx.extra) == schemas[tx.tx_type], 'Field transaksi tidak sesuai skema')
    balance = state.balances.get(tx.member_id, 0)
    loan_id = tx.extra.get('loan_id')
    if loan_id is not None:
        require(isinstance(loan_id, str) and bool(loan_id.strip()), 'ID pinjaman salah')

    if tx.tx_type == 'deposit':
        state.balances[tx.member_id] = balance + tx.amount
    elif tx.tx_type == 'withdrawal':
        require(balance >= tx.amount, 'Saldo tidak cukup')
        require(all(type(tx.extra[k]) is int for k in ('saldo_sebelum', 'saldo_sesudah')),
                'Field saldo harus integer')
        require(tx.extra['saldo_sebelum'] == balance and
                tx.extra['saldo_sesudah'] == balance - tx.amount, 'Metadata saldo tidak cocok')
        state.balances[tx.member_id] = balance - tx.amount
    elif tx.tx_type == 'loan_request':
        require(loan_id not in state.loans, 'ID pinjaman sudah ada')
        tenor = tx.extra['tenor_bulan']
        require(type(tenor) is int and tenor > 0, 'Tenor harus integer positif')
        require(tx.extra['status'] == 'diajukan', 'Status awal harus diajukan')
        state.loans[loan_id] = dict(member_id=tx.member_id, amount=tx.amount,
                                   outstanding=tx.amount, sisa_tenor=tenor, status='diajukan')
    else:
        require(loan_id in state.loans, 'Pinjaman tidak ditemukan')
        loan = state.loans[loan_id]
        require(loan['member_id'] == tx.member_id, 'Anggota bukan pemilik pinjaman')
        if tx.tx_type == 'loan_approval':
            require(loan['status'] == 'diajukan', 'Pinjaman tidak sedang diajukan')
            require(tx.amount == loan['amount'], 'Nominal persetujuan tidak cocok')
            loan['status'] = 'disetujui'
        elif tx.tx_type == 'loan_disbursement':
            require(loan['status'] == 'disetujui', 'Pinjaman belum disetujui/sudah dicairkan')
            require(tx.amount == loan['amount'], 'Nominal pencairan tidak cocok')
            loan['status'] = 'dicairkan'
            state.balances[tx.member_id] = balance + tx.amount
        else:
            require(loan['status'] == 'dicairkan', 'Pinjaman belum dicairkan/sudah lunas')
            require(tx.amount <= loan['outstanding'], 'Angsuran melebihi sisa utang')
            remaining = loan['outstanding'] - tx.amount
            expected = 0 if remaining == 0 else loan['sisa_tenor'] - 1
            require(remaining == 0 or expected > 0, 'Angsuran terakhir harus melunasi utang')
            require(type(tx.extra['sisa_tenor']) is int and tx.extra['sisa_tenor'] == expected,
                    'Sisa tenor tidak sesuai')
            loan.update(outstanding=remaining, sisa_tenor=expected)
            if remaining == 0:
                loan['status'] = 'lunas'
    state.seen.add(tx.tx_id)


def compute_merkle_root(transactions):
    layer = [digest(tx.to_dict()) for tx in transactions]
    if not layer:
        return hashlib.sha256(b'').hexdigest()
    while len(layer) > 1:
        if len(layer) % 2:
            layer.append(layer[-1])
        layer = [hashlib.sha256(bytes.fromhex(layer[i]) + bytes.fromhex(layer[i+1])).hexdigest()
                 for i in range(0, len(layer), 2)]
    return layer[0]


@dataclass
class Block:
    index: int
    transactions: list
    timestamp: int = field(default_factory=lambda: int(time.time()))
    previous_hash: str = ZERO_HASH
    merkle_root: str = field(init=False)
    validator_signatures: list = field(default_factory=list)
    block_hash: str = ''

    def __post_init__(self):
        self.transactions = copy.deepcopy(self.transactions)
        self.merkle_root = compute_merkle_root(self.transactions)

    def header(self):
        return dict(index=self.index, timestamp=self.timestamp,
                    previous_hash=self.previous_hash, merkle_root=self.merkle_root,
                    network=NETWORK)

    def compute_header_hash(self):
        return digest(self.header())


def link_block(block, parent_block):
    block.previous_hash = parent_block.block_hash


def validate_block(block, parent, state, permission_list):
    require(type(block.index) is int and block.index == (parent.index + 1 if parent else 0),
            'Urutan index salah')
    require(block.previous_hash == (parent.block_hash if parent else ZERO_HASH),
            'Previous hash tidak cocok')
    require(type(block.timestamp) is int and block.timestamp >= (parent.timestamp if parent else 0),
            'Timestamp block tidak valid')
    require(block.merkle_root == compute_merkle_root(block.transactions), 'Merkle root tidak cocok')
    if parent is None:
        require(not block.transactions and block.timestamp == 0, 'Genesis harus kosong dan waktu 0')
    else:
        require(bool(block.transactions), 'Block transaksi kosong')
    working = copy.deepcopy(state)
    for tx in block.transactions:
        require(tx.timestamp <= block.timestamp, 'Transaksi lebih baru dari block')
        apply_transaction(tx, working, permission_list)
    return working


def verify_certificate(block, validator_public):
    require(block.block_hash == block.compute_header_hash(), 'Hash header tidak cocok')
    unique = set()
    for seal in block.validator_signatures:
        name = seal['validator']
        require(name in validator_public and name not in unique,
                'Validator asing atau signature validator duplikat')
        require(verify(validator_public[name], seal['signature'], canonical(block.header())),
                'Signature validator tidak valid')
        unique.add(name)
    require(len(unique) >= QUORUM, 'Kuorum minimal 3 validator unik tidak tercapai')


def replay_chain(chain, permission_list, validator_public, trusted_genesis):
    """Rekonstruksi state dari genesis; audit isi, signature, urutan dan kuorum."""
    require(bool(chain), 'Chain kosong')
    require(chain[0].block_hash == trusted_genesis, 'Genesis tidak dikenal')
    state, parent = State(), None
    for block in chain:
        state = validate_block(block, parent, state, permission_list)
        verify_certificate(block, validator_public)
        parent = block
    return state


class ValidatorNode:
    def __init__(self, name, wallet, permission_list, validator_public):
        self.name, self.wallet = name, wallet
        self.permission_list = copy.deepcopy(permission_list)
        self.validator_public = copy.deepcopy(validator_public)
        self.chain = []

    def approve(self, candidate, trusted_genesis):
        state = replay_chain(self.chain, self.permission_list, self.validator_public, trusted_genesis)
        validate_block(candidate, self.chain[-1], state, self.permission_list)
        return dict(validator=self.name, signature=self.wallet.sign(canonical(candidate.header())))


class ObserverNode:
    def __init__(self, permission_list, validator_public, trusted_genesis):
        self._permission_list = copy.deepcopy(permission_list)
        self._validator_public = copy.deepcopy(validator_public)
        self._genesis = trusted_genesis
        self._chain = []

    def sync(self, chain):
        replay_chain(chain, self._permission_list, self._validator_public, self._genesis)
        self._chain = copy.deepcopy(chain)

    def snapshot(self):
        return copy.deepcopy(self._chain)

    def get_transaction_history(self, member_id):
        return [tx.to_dict() for b in self._chain for tx in b.transactions if tx.member_id == member_id]

    def verify_integrity(self):
        replay_chain(self._chain, self._permission_list, self._validator_public, self._genesis)
        return True


class Auditor:
    def __init__(self, observer):
        self.observer = observer

    def inspect_member_history(self, member_id):
        return self.observer.get_transaction_history(member_id)

    def verify_ledger_integrity(self):
        return self.observer.verify_integrity()


class KoperasiBlockchain:
    def __init__(self):
        self.teller = Wallet()
        # Konfigurasi keanggotaan tepercaya untuk sesi praktikum ini.
        self.permission_list = {'TELLER-01': self.teller.public_pem}
        wallets = {name: Wallet() for name in VALIDATOR_NAMES}
        self.validator_public = {name: w.public_pem for name, w in wallets.items()}
        genesis = Block(0, [], timestamp=0)
        genesis.block_hash = genesis.compute_header_hash()
        genesis.validator_signatures = [dict(validator=name, signature=w.sign(canonical(genesis.header())))
                                        for name, w in wallets.items()]
        self.trusted_genesis = genesis.block_hash
        self.chain = [genesis]
        self.state = State()
        self.mempool = []
        self.nodes = [ValidatorNode(name, w, self.permission_list, self.validator_public)
                      for name, w in wallets.items()]
        for node in self.nodes:
            node.chain = copy.deepcopy(self.chain)
        self.observer = ObserverNode(self.permission_list, self.validator_public, self.trusted_genesis)
        self.observer.sync(self.chain)

    def pending_state(self):
        state = copy.deepcopy(self.state)
        for tx in self.mempool:
            apply_transaction(tx, state, self.permission_list)
        return state

    def make_transaction(self, kind, member, amount, extra=None):
        if kind == 'withdrawal' and extra is None:
            before = self.pending_state().balances.get(member, 0)
            extra = dict(saldo_sebelum=before, saldo_sesudah=before - amount)
        return Transaction(kind, member, amount, 'TELLER-01', copy.deepcopy(extra or {})).sign(self.teller)

    def submit(self, tx):
        working = self.pending_state()
        require(tx.timestamp <= int(time.time()), 'Waktu transaksi di masa depan')
        apply_transaction(tx, working, self.permission_list)
        self.mempool.append(copy.deepcopy(tx))
        # self.state tidak berubah: saldo final hanya berubah pada commit.

    def propose_block(self):
        require(bool(self.mempool), 'Mempool kosong')
        candidate = Block(self.chain[-1].index + 1, self.mempool,
                          timestamp=max(int(time.time()), self.chain[-1].timestamp))
        link_block(candidate, self.chain[-1])
        return candidate

    def commit_candidate(self, block):
        new_state = validate_block(block, self.chain[-1], self.state, self.permission_list)
        verify_certificate(block, self.validator_public)
        # Semua pemeriksaan harus berhasil sebelum state final berubah.
        self.chain.append(copy.deepcopy(block))
        self.state = new_state
        committed_ids = {tx.tx_id for tx in block.transactions}
        remaining = [tx for tx in self.mempool if tx.tx_id not in committed_ids]
        self.mempool = []
        for tx in remaining:
            try:
                self.submit(tx)  # validasi ulang antrean terhadap state terbaru
            except ValueError:
                pass
        self.observer.sync(self.chain)

    def run_authority_consensus(self, offline=()):
        """Simulasi lokal: validasi independen + 3 tanda tangan unik. Bukan IBFT."""
        block = self.propose_block()
        online = [n for n in self.nodes if n.name not in offline]
        for node in online:
            # Catch-up sebelum voting; salinan berbeda untuk setiap node.
            replay_chain(self.chain, node.permission_list, node.validator_public, self.trusted_genesis)
            node.chain = copy.deepcopy(self.chain)
            try:
                block.validator_signatures.append(node.approve(block, self.trusted_genesis))
            except ValueError:
                continue
        count = len(block.validator_signatures)
        if count < QUORUM:
            return False, count    # mempool tetap; saldo dan chain final tidak berubah
        block.block_hash = block.compute_header_hash()
        self.commit_candidate(block)
        for node in online:
            node.chain = copy.deepcopy(self.chain)
        return True, count


def demo():
    app = KoperasiBlockchain()
    print('BLOCKCHAIN KOPERASI - PRAKTIKUM 1')
    print('Simulasi authority-based lokal, kuorum 3/4. BUKAN IBFT lengkap.')

    def send(kind, member, amount, extra=None):
        tx = app.make_transaction(kind, member, amount, extra)
        app.submit(tx)
        print('  MEMPOOL:', kind, member, f'Rp{amount:,}', extra or '')
        return tx

    def commit(offline=()):
        ok, count = app.run_authority_consensus(offline)
        print(f'  KONSENSUS: {count}/4 ({count/4:.0%}),', 'DITERIMA' if ok else 'DITOLAK')
        print('  Saldo FINAL:', app.state.balances)
        return ok

    print('\n1. SETORAN DAN PENARIKAN -> BLOCK 1')
    tx1 = send('deposit', 'AGT-001', 500000)
    send('withdrawal', 'AGT-001', 100000)
    print('  Sebelum commit, saldo final AGT-001:', app.state.balances.get('AGT-001', 0))
    commit()

    print('\n2. PENGAJUAN, PERSETUJUAN DAN PENCAIRAN -> BLOCK 2')
    send('loan_request', 'AGT-002', 2000000,
         dict(loan_id='PINJ-001', tenor_bulan=12, status='diajukan'))
    send('loan_approval', 'AGT-002', 2000000, dict(loan_id='PINJ-001'))
    send('loan_disbursement', 'AGT-002', 2000000, dict(loan_id='PINJ-001'))
    commit()

    print('\n3. ANGSURAN TUNAI -> BLOCK 3; SATU VALIDATOR OFFLINE')
    send('installment_payment', 'AGT-002', 180000, dict(loan_id='PINJ-001', sisa_tenor=11))
    commit(VALIDATOR_NAMES[-1:])
    print('  Pinjaman:', app.state.loans['PINJ-001'])
    auditor = Auditor(app.observer)
    print('\n4. AUDITOR: INTEGRITAS =', auditor.verify_ledger_integrity())
    for tx in auditor.inspect_member_history('AGT-002'):
        print(' ', tx['tx_type'], tx['amount'], tx['extra'])

    print('\n5. UJI MANIPULASI PADA SALINAN CHAIN')
    altered = app.observer.snapshot()
    altered[1].transactions[0].amount = 50000000
    try:
        replay_chain(altered, app.permission_list, app.validator_public, app.trusted_genesis)
    except ValueError as exc:
        print('  TERDETEKSI:', exc)
    print('  Chain asli tetap valid:', auditor.verify_ledger_integrity())

    print('\n6. UJI OPERATOR ASING, PENYAMARAN DAN REPLAY')
    rogue = Wallet()
    attempts = [Transaction('deposit', 'AGT-003', 100000, 'TELLER-ROGUE').sign(rogue),
                Transaction('deposit', 'AGT-003', 100000, 'TELLER-01').sign(rogue), tx1]
    for tx in attempts:
        try:
            app.submit(tx)
        except ValueError as exc:
            print('  DITOLAK:', exc)

    print('\n7. KUORUM GAGAL: 1/4 VALIDATOR; SALDO TIDAK BOLEH BERUBAH')
    send('deposit', 'AGT-004', 300000)
    commit(VALIDATOR_NAMES[1:])
    print('  Saldo FINAL AGT-004:', app.state.balances.get('AGT-004', 0))
    print('  Transaksi tetap menunggu di mempool:', len(app.mempool))
    print('\n8. COBA ULANG SAAT VALIDATOR KEMBALI ONLINE')
    commit()
    print('  Seluruh salinan validator valid:', all(
        replay_chain(n.chain, n.permission_list, n.validator_public, app.trusted_genesis) == app.state
        for n in app.nodes))
    print('  Audit akhir:', auditor.verify_ledger_integrity())
    print('\nOpsi lain: --test untuk uji otomatis.')


class RegressionTests(unittest.TestCase):
    """Uji perilaku penting, termasuk serangan yang lolos di versi sebelumnya."""
    def setUp(self):
        self.app = KoperasiBlockchain()

    def deposit(self, amount=500000):
        tx = self.app.make_transaction('deposit', 'AGT-001', amount)
        self.app.submit(tx)
        return tx

    def test_final_state_only_after_quorum(self):
        self.deposit()
        self.assertEqual(self.app.state.balances, {})
        for offline in (VALIDATOR_NAMES[1:], VALIDATOR_NAMES[2:]):
            self.assertFalse(self.app.run_authority_consensus(offline)[0])
            self.assertEqual(self.app.state.balances, {})
            self.assertEqual(len(self.app.chain), 1)
        self.assertTrue(self.app.run_authority_consensus(VALIDATOR_NAMES[-1:])[0])
        self.assertEqual(self.app.state.balances['AGT-001'], 500000)
        self.assertEqual(len(self.app.mempool), 0)

    def test_identity_binding_and_unknown_operator(self):
        rogue = Wallet()
        for operator in ('TELLER-01', 'ROGUE'):
            with self.assertRaises(ValueError):
                self.app.submit(Transaction('deposit', 'A', 1, operator).sign(rogue))

    def test_replay_pending_and_committed(self):
        tx = self.deposit()
        with self.assertRaises(ValueError):
            self.app.submit(tx)
        self.app.run_authority_consensus()
        with self.assertRaises(ValueError):
            self.app.submit(tx)

    def test_invalid_amount_type_and_transaction_type(self):
        for amount in (0, -10, 1.5, True):
            with self.assertRaises(ValueError):
                self.app.submit(self.app.make_transaction('deposit', 'A', amount))
        with self.assertRaises(ValueError):
            self.app.submit(self.app.make_transaction('unknown', 'A', 10))

    def test_pending_double_spend_and_balance_metadata(self):
        self.deposit(100)
        self.app.submit(self.app.make_transaction('withdrawal', 'AGT-001', 80))
        with self.assertRaises(ValueError):
            self.app.submit(self.app.make_transaction('withdrawal', 'AGT-001', 30))
        with self.assertRaises(ValueError):
            self.app.submit(self.app.make_transaction('withdrawal', 'AGT-001', 10,
                            dict(saldo_sebelum=999, saldo_sesudah=989)))

    def test_validator_rejects_tampered_candidate(self):
        self.deposit()
        block = self.app.propose_block()
        block.transactions[0].amount = 999
        block.merkle_root = compute_merkle_root(block.transactions)
        for node in self.app.nodes:
            with self.assertRaises(ValueError):
                node.approve(block, self.app.trusted_genesis)

    def test_duplicate_validator_seals_rejected(self):
        self.deposit()
        block = self.app.propose_block()
        seal = self.app.nodes[0].approve(block, self.app.trusted_genesis)
        block.validator_signatures = [seal, seal, seal]
        block.block_hash = block.compute_header_hash()
        with self.assertRaises(ValueError):
            self.app.commit_candidate(block)
        self.assertEqual(self.app.state.balances, {})

    def test_audit_tampering_and_observer_isolation(self):
        tx = self.deposit()
        tx.amount = 1  # mempool harus menyimpan salinan
        self.app.run_authority_consensus()
        for change in ('payload', 'header', 'parent', 'signature'):
            chain = self.app.observer.snapshot()
            block = chain[-1]
            if change == 'payload':
                block.transactions[0].amount = 1
            elif change == 'header':
                block.timestamp += 1
            elif change == 'parent':
                block.previous_hash = ZERO_HASH
            else:
                block.validator_signatures[0]['signature'] = '00'
            with self.assertRaises(ValueError):
                replay_chain(chain, self.app.permission_list, self.app.validator_public,
                             self.app.trusted_genesis)
        history = self.app.observer.get_transaction_history('AGT-001')
        history[0]['extra']['fake'] = 1
        self.assertTrue(self.app.observer.verify_integrity())
        self.assertIsNot(self.app.nodes[0].chain[-1], self.app.nodes[1].chain[-1])
        self.assertEqual(self.app.state.balances['AGT-001'], 500000)

    def test_loan_lifecycle_and_rules(self):
        def send(kind, member='A', amount=100, **extra):
            self.app.submit(self.app.make_transaction(kind, member, amount, extra))
        send('loan_request', loan_id='L1', tenor_bulan=2, status='diajukan')
        with self.assertRaises(ValueError):
            send('loan_disbursement', loan_id='L1')
        send('loan_approval', loan_id='L1')
        for member, amount in (('B', 100), ('A', 999)):
            with self.assertRaises(ValueError):
                send('loan_disbursement', member, amount, loan_id='L1')
        send('loan_disbursement', loan_id='L1')
        with self.assertRaises(ValueError):
            send('loan_disbursement', loan_id='L1')
        send('installment_payment', amount=40, loan_id='L1', sisa_tenor=1)
        with self.assertRaises(ValueError):
            send('installment_payment', amount=20, loan_id='L1', sisa_tenor=0)
        send('installment_payment', amount=60, loan_id='L1', sisa_tenor=0)
        self.app.run_authority_consensus()
        self.assertEqual(self.app.state.loans['L1']['status'], 'lunas')
        self.assertEqual(self.app.state.loans['L1']['outstanding'], 0)
        self.assertEqual(self.app.state.balances['A'], 100)
        self.assertEqual(replay_chain(self.app.chain, self.app.permission_list,
                                     self.app.validator_public, self.app.trusted_genesis), self.app.state)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--test', action='store_true', help='Jalankan uji regresi')
    args = parser.parse_args()
    if args.test:
        unittest.main(argv=['blockchain_koperasi.py'], verbosity=2)
    else:
        demo()