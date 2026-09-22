"""
Tugas Besar - Rekayasa Ulang Praktikum I: Blockchain Permissioned
untuk Jaringan Konsorsium Koperasi Simpan Pinjam

Versi 2: melengkapi 3 hal dari versi sebelumnya agar makin ketat mengikuti
"Laporan Desain Jaringan Blockchain untuk Industri Finansial":
  1. Field transaksi selengkap Bagian 1.3 (saldo sebelum/sesudah, loan_id)
  2. ObserverNode & Auditor sebagai objek terpisah (read-only, sesuai Bagian 1.2)
  3. previous_hash ditautkan lewat fungsi terpisah link_block(), meniru pola
     assignment terpisah pada Kode 1.13 modul praktikum (bukan langsung
     dimasukkan saat Block() dibuat)
"""

import hashlib
import json
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature


# ============================================================
# 1. PEMBANGKITAN KUNCI (kriptografi kurva eliptik / ECC)
# ============================================================
def generate_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def pubkey_to_pem(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


VALIDATOR_NAMES = [
    "Pengurus Pusat",
    "Pengurus Koperasi",
    "Pengurus Pengawas",
    "Otoritas Konsorsium",
]

validators = {}
for name in VALIDATOR_NAMES:
    priv, pub = generate_keypair()
    validators[name] = {"private": priv, "public": pub}

teller_private, teller_public = generate_keypair()
rogue_private, rogue_public = generate_keypair()


# ============================================================
# 2. PERMISSION LIST (Whitelist Public Key)
# ============================================================
permission_list = {}


def register_operator(operator_id, public_key):
    permission_list[operator_id] = pubkey_to_pem(public_key)


def is_registered(operator_id):
    return operator_id in permission_list


register_operator("TELLER-01", teller_public)


# ============================================================
# 3. "SALINAN LEDGER LOKAL" PARTICIPANT NODE
#    dipakai untuk cek saldo & status pinjaman (Bagian 4.3 poin 1)
# ============================================================
member_balances = {}
loans = {}
_loan_counter = [1]


def get_balance(member_id):
    return member_balances.get(member_id, 0)


def next_loan_id():
    loan_id = f"PINJ-{_loan_counter[0]:03d}"
    _loan_counter[0] += 1
    return loan_id


def approve_loan(loan_id):
    """Persetujuan pinjaman oleh Operator berwenang - state internal,
    dilakukan sebelum pencairan (Bagian 1.3 laporan: 'Pencairan pinjaman
    dieksekusi setelah pengajuan disetujui')."""
    if loan_id in loans:
        loans[loan_id]["status"] = "disetujui"


# ============================================================
# 4. TRANSAKSI - field selengkap Bagian 1.3 laporan
# ============================================================
class Transaction:
    def __init__(self, tx_type, member_id, amount, operator_id, extra=None):
        self.tx_type = tx_type
        self.member_id = member_id
        self.amount = amount
        self.operator_id = operator_id
        self.timestamp = time.time()
        self.extra = extra or {}
        self.signature = None

    def _payload(self):
        payload = {
            "tx_type": self.tx_type,
            "member_id": self.member_id,
            "amount": self.amount,
            "operator_id": self.operator_id,
            "timestamp": self.timestamp,
            "extra": self.extra,
        }
        return json.dumps(payload, sort_keys=True).encode("utf-8")

    def payload_hash(self):
        return hashlib.sha256(self._payload()).digest()

    def sign(self, private_key):
        self.signature = private_key.sign(self.payload_hash(), ec.ECDSA(hashes.SHA256()))

    def verify_signature(self, public_key):
        if self.signature is None:
            return False
        try:
            public_key.verify(self.signature, self.payload_hash(), ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False

    def to_dict(self):
        return {
            "tx_type": self.tx_type,
            "member_id": self.member_id,
            "amount": self.amount,
            "operator_id": self.operator_id,
            "timestamp": self.timestamp,
            "extra": self.extra,
            "signature": self.signature.hex() if self.signature else None,
        }


# ---- Helper pembuatan transaksi per jenis, mengisi field sesuai Bagian 1.3 ----
def make_deposit(member_id, amount, operator_id, private_key):
    """Setoran simpanan - ID Anggota, nominal, timestamp."""
    tx = Transaction("deposit", member_id, amount, operator_id)
    tx.sign(private_key)
    return tx


def make_withdrawal(member_id, amount, operator_id, private_key):
    """Penarikan simpanan - ID Anggota, nominal, saldo sebelum/sesudah."""
    saldo_sebelum = get_balance(member_id)
    tx = Transaction("withdrawal", member_id, amount, operator_id, extra={
        "saldo_sebelum": saldo_sebelum,
        "saldo_sesudah": saldo_sebelum - amount,
    })
    tx.sign(private_key)
    return tx


def make_loan_request(member_id, amount, tenor_bulan, operator_id, private_key):
    """Pengajuan pinjaman - ID Anggota, nominal pinjaman, tenor, status persetujuan."""
    loan_id = next_loan_id()
    tx = Transaction("loan_request", member_id, amount, operator_id, extra={
        "loan_id": loan_id,
        "tenor_bulan": tenor_bulan,
        "status": "diajukan",
    })
    tx.sign(private_key)
    return tx


def make_loan_disbursement(member_id, amount, loan_id, operator_id, private_key):
    """Pencairan pinjaman - dieksekusi setelah pengajuan disetujui Operator berwenang."""
    tx = Transaction("loan_disbursement", member_id, amount, operator_id, extra={
        "loan_id": loan_id,
    })
    tx.sign(private_key)
    return tx


def make_installment(member_id, loan_id, amount, sisa_tenor, operator_id, private_key):
    """Pembayaran angsuran - ID pinjaman terkait, nominal angsuran, sisa tenor."""
    tx = Transaction("installment_payment", member_id, amount, operator_id, extra={
        "loan_id": loan_id,
        "sisa_tenor": sisa_tenor,
    })
    tx.sign(private_key)
    return tx


def participant_node_verify(tx, signer_public_key):
    """
    Simulasi Participant Node (Bagian 4.3): verifikasi signature, cek whitelist,
    cek saldo/status akun terhadap salinan ledger lokal, baru diteruskan ke Mempool.
    """
    if not is_registered(tx.operator_id):
        return False, "DITOLAK: operator_id tidak terdaftar di Permission List (whitelist)"
    if not tx.verify_signature(signer_public_key):
        return False, "DITOLAK: signature tidak valid"

    if tx.tx_type == "withdrawal" and get_balance(tx.member_id) < tx.amount:
        return False, "DITOLAK: saldo tidak mencukupi"

    if tx.tx_type == "loan_disbursement":
        loan_id = tx.extra.get("loan_id")
        loan = loans.get(loan_id)
        if loan is None or loan["status"] != "disetujui":
            return False, "DITOLAK: pinjaman belum disetujui / loan_id tidak ditemukan"

    if tx.tx_type == "installment_payment" and tx.extra.get("loan_id") not in loans:
        return False, "DITOLAK: loan_id tidak ditemukan"

    # Lolos verifikasi -> perbarui salinan ledger lokal Participant Node
    if tx.tx_type == "deposit":
        member_balances[tx.member_id] = get_balance(tx.member_id) + tx.amount
    elif tx.tx_type == "withdrawal":
        member_balances[tx.member_id] = get_balance(tx.member_id) - tx.amount
    elif tx.tx_type == "loan_request":
        loans[tx.extra["loan_id"]] = {
            "member_id": tx.member_id, "amount": tx.amount,
            "tenor_bulan": tx.extra["tenor_bulan"], "status": "diajukan",
            "sisa_tenor": tx.extra["tenor_bulan"],
        }
    elif tx.tx_type == "loan_disbursement":
        loans[tx.extra["loan_id"]]["status"] = "dicairkan"
        member_balances[tx.member_id] = get_balance(tx.member_id) + tx.amount
    elif tx.tx_type == "installment_payment":
        loans[tx.extra["loan_id"]]["sisa_tenor"] = tx.extra["sisa_tenor"]

    return True, "DITERIMA: masuk Mempool"


# ============================================================
# 5. MERKLE ROOT
# ============================================================
def compute_merkle_root(transactions):
    if not transactions:
        return hashlib.sha256(b"").hexdigest()
    layer = [
        hashlib.sha256(json.dumps(tx.to_dict(), sort_keys=True).encode("utf-8")).hexdigest()
        for tx in transactions
    ]
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])
        layer = [
            hashlib.sha256((layer[i] + layer[i + 1]).encode("utf-8")).hexdigest()
            for i in range(0, len(layer), 2)
        ]
    return layer[0]


# ============================================================
# 6. BLOCK - previous_hash ditautkan terpisah lewat link_block()
# ============================================================
class Block:
    def __init__(self, index, transactions):
        self.index = index
        self.timestamp = time.time()
        self.previous_hash = None  # belum ditautkan; lihat link_block()
        self.transactions = transactions
        self.merkle_root = compute_merkle_root(transactions)
        self.validator_signatures = []
        self.block_hash = None

    def header_dict(self):
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "merkle_root": self.merkle_root,
        }

    def compute_header_hash(self):
        payload = json.dumps(self.header_dict(), sort_keys=True).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()


def link_block(block, parent_block):
    """
    Menautkan block baru ke block induk secara eksplisit - meniru pola
    'block_B.parent_hash = compute_hash(block_A)' pada Kode 1.13 modul
    praktikum, bukan langsung dimasukkan saat objek Block dibuat.
    """
    block.previous_hash = parent_block.block_hash


# ============================================================
# 7. KONSENSUS IBFT
# ============================================================
def run_ibft_consensus(block, offline_or_byzantine=None, threshold=2 / 3):
    offline_or_byzantine = offline_or_byzantine or []
    header_hash_hex = block.compute_header_hash()
    header_hash_bytes = bytes.fromhex(header_hash_hex)

    approvals = 0
    for v_name, keys in validators.items():
        if v_name in offline_or_byzantine:
            continue
        signature = keys["private"].sign(header_hash_bytes, ec.ECDSA(hashes.SHA256()))
        block.validator_signatures.append({"validator": v_name, "signature": signature.hex()})
        approvals += 1

    ratio = approvals / len(validators)
    if ratio >= threshold:
        block.block_hash = header_hash_hex
        return True, ratio
    block.block_hash = None
    return False, ratio


# ============================================================
# 8. VALIDASI RANTAI
# ============================================================
def is_chain_valid(chain, threshold=2 / 3):
    for i, block in enumerate(chain):
        if i > 0 and block.previous_hash != chain[i - 1].block_hash:
            print(f"  ! Block id={block.index}: previous_hash tidak cocok dengan block sebelumnya")
            return False

        recalculated_merkle = compute_merkle_root(block.transactions)
        if recalculated_merkle != block.merkle_root:
            print(f"  ! Block id={block.index}: merkle_root tidak cocok (transaksi dimanipulasi)")
            return False

        recalculated_header_hash = block.compute_header_hash()
        if recalculated_header_hash != block.block_hash:
            print(f"  ! Block id={block.index}: block_hash tidak cocok (header dimanipulasi)")
            return False

        header_hash_bytes = bytes.fromhex(recalculated_header_hash)
        valid_sign = 0
        for entry in block.validator_signatures:
            v_pub = validators[entry["validator"]]["public"]
            try:
                v_pub.verify(bytes.fromhex(entry["signature"]), header_hash_bytes, ec.ECDSA(hashes.SHA256()))
                valid_sign += 1
            except InvalidSignature:
                print(f"  ! Block id={block.index}: signature validator {entry['validator']} tidak sah")
                return False
        if valid_sign / len(validators) < threshold:
            print(f"  ! Block id={block.index}: validator_signatures tidak mencapai ambang 66% "
                  f"({valid_sign}/{len(validators)})")
            return False

    return True


# ============================================================
# 9. OBSERVER NODE & AUDITOR - akses read-only (Bagian 1.2 & Diagram Arsitektur)
# ============================================================
class ObserverNode:
    """
    Node non-validator yang menyimpan salinan ledger untuk Auditor.
    Disinkronkan setelah block final di-commit Validator (langkah 6 pada
    Diagram Arsitektur Beranotasi). Tidak punya method untuk mengubah ledger.
    """
    def __init__(self):
        self.synced_chain = []

    def sync(self, chain):
        self.synced_chain = list(chain)

    def get_transaction_history(self, member_id):
        history = []
        for block in self.synced_chain:
            for tx in block.transactions:
                if tx.member_id == member_id:
                    history.append(tx.to_dict())
        return history

    def get_transaction_objects(self, member_id):
        """Sama seperti get_transaction_history, tapi mengembalikan objek
        Transaction (bukan dict) supaya bisa ditampilkan ringkas di terminal."""
        return [tx for block in self.synced_chain for tx in block.transactions
                if tx.member_id == member_id]


class Auditor:
    """
    Auditor (akuntan publik, OJK/Dinas Koperasi, anggota koperasi): hanya
    memiliki akses baca lewat Observer Node, tanpa kemampuan mengubah status
    blockchain (Bagian 1.2 laporan).
    """
    def __init__(self, auditor_id, observer_node):
        self.auditor_id = auditor_id
        self.observer_node = observer_node

    def verify_ledger_integrity(self):
        return is_chain_valid(self.observer_node.synced_chain)

    def inspect_member_history(self, member_id):
        return self.observer_node.get_transaction_history(member_id)

    def inspect_member_history_objects(self, member_id):
        return self.observer_node.get_transaction_objects(member_id)


# ============================================================
# 10. HELPER TAMPILAN - supaya output terminal rapi dan mudah dibaca
# ============================================================
LINE_WIDTH = 64
TX_LABEL = {
    "deposit": "Setoran",
    "withdrawal": "Penarikan",
    "loan_request": "Pengajuan pinjaman",
    "loan_disbursement": "Pencairan pinjaman",
    "installment_payment": "Angsuran",
}


def rp(amount):
    """Format angka jadi Rp x.xxx.xxx."""
    return "Rp" + f"{amount:,.0f}".replace(",", ".")


def section(title):
    print("\n" + "-" * LINE_WIDTH)
    print(f" {title}")
    print("-" * LINE_WIDTH)


def status_line(ok, tag, keterangan=""):
    mark = "OK " if ok else "TOLAK"
    line = f"  [{mark}] {tag}"
    if keterangan:
        line += f"  ({keterangan})"
    print(line)


def block_result_line(block_label, committed, ratio, n_approve, n_total):
    hasil = "SAH & FINAL" if committed else "DITOLAK"
    print(f"  -> Konsensus IBFT {block_label}: {hasil}  "
          f"[{n_approve}/{n_total} validator setuju, {ratio:.0%}]")


def print_tx_summary(tx):
    """Satu baris ringkas per transaksi, tanpa signature hex yang panjang."""
    label = TX_LABEL.get(tx.tx_type, tx.tx_type)
    detail = f"{label:<20} {tx.member_id:<9} {rp(tx.amount):>14}"
    if tx.tx_type == "withdrawal":
        detail += f"   saldo {rp(tx.extra['saldo_sebelum'])} -> {rp(tx.extra['saldo_sesudah'])}"
    elif tx.tx_type == "loan_request":
        detail += f"   {tx.extra['loan_id']}, tenor {tx.extra['tenor_bulan']} bln, status: {tx.extra['status']}"
    elif tx.tx_type == "loan_disbursement":
        detail += f"   {tx.extra['loan_id']}"
    elif tx.tx_type == "installment_payment":
        detail += f"   {tx.extra['loan_id']}, sisa tenor: {tx.extra['sisa_tenor']} bln"
    print("    " + detail)


# ============================================================
# 11. DEMO / SKENARIO SESUAI DOKUMEN DESAIN
# ============================================================
if __name__ == "__main__":
    n_validators = len(validators)

    section("TAHAP 1 - Setoran & Penarikan Simpanan (Block A)")
    tx1 = make_deposit("AGT-001", 500000, "TELLER-01", teller_private)
    ok, msg = participant_node_verify(tx1, teller_public)
    status_line(ok, f"Setoran {rp(tx1.amount)} - {tx1.member_id}")

    tx2 = make_withdrawal("AGT-001", 100000, "TELLER-01", teller_private)
    ok, msg = participant_node_verify(tx2, teller_public)
    status_line(ok, f"Penarikan {rp(tx2.amount)} - {tx2.member_id}",
                f"saldo {rp(tx2.extra['saldo_sebelum'])} -> {rp(tx2.extra['saldo_sesudah'])}")

    block_A = Block(index=1, transactions=[tx1, tx2])
    block_A.previous_hash = "0" * 64  # genesis block, tidak memiliki induk
    committed, ratio = run_ibft_consensus(block_A)
    block_result_line("Block A", committed, ratio, round(ratio * n_validators), n_validators)

    section("TAHAP 2 - Pengajuan & Pencairan Pinjaman (Block B)")
    tx3 = make_loan_request("AGT-002", 2000000, 12, "TELLER-01", teller_private)
    ok, msg = participant_node_verify(tx3, teller_public)
    status_line(ok, f"Pengajuan pinjaman {rp(tx3.amount)} - {tx3.member_id}", f"loan_id {tx3.extra['loan_id']}")

    approve_loan(tx3.extra["loan_id"])  # disetujui Operator berwenang sebelum dicairkan
    tx4 = make_loan_disbursement("AGT-002", 2000000, tx3.extra["loan_id"], "TELLER-01", teller_private)
    ok, msg = participant_node_verify(tx4, teller_public)
    status_line(ok, f"Pencairan pinjaman {rp(tx4.amount)} - {tx4.member_id}", f"loan_id {tx4.extra['loan_id']}")

    block_B = Block(index=2, transactions=[tx3, tx4])
    link_block(block_B, block_A)  # eksplisit, meniru pola modul
    committed, ratio = run_ibft_consensus(block_B)
    block_result_line("Block B", committed, ratio, round(ratio * n_validators), n_validators)

    section("TAHAP 3 - Pembayaran Angsuran (Block C)")
    tx5 = make_installment("AGT-002", tx3.extra["loan_id"], 180000, 11, "TELLER-01", teller_private)
    ok, msg = participant_node_verify(tx5, teller_public)
    status_line(ok, f"Angsuran {rp(tx5.amount)} - {tx5.member_id}", f"sisa tenor {tx5.extra['sisa_tenor']} bln")

    block_C = Block(index=3, transactions=[tx5])
    link_block(block_C, block_B)
    committed, ratio = run_ibft_consensus(block_C)
    block_result_line("Block C", committed, ratio, round(ratio * n_validators), n_validators)

    chain = [block_A, block_B, block_C]

    section("SINKRONISASI KE OBSERVER NODE & VERIFIKASI AUDITOR")
    observer = ObserverNode()
    observer.sync(chain)
    auditor = Auditor("AUD-01", observer)

    print("  Riwayat transaksi AGT-002 (dibaca Auditor lewat Observer Node):")
    for tx in auditor.inspect_member_history_objects("AGT-002"):
        print_tx_summary(tx)
    print(f"\n  Verifikasi integritas ledger oleh Auditor -> "
          f"{'VALID' if auditor.verify_ledger_integrity() else 'TIDAK VALID'}")

    section("SKENARIO UJI 1 - Manipulasi Isi Transaksi pada Block A")
    print(f"  Sebelum manipulasi -> chain valid: {is_chain_valid(chain)}")
    tx1.amount = 50000000
    print("  Nominal setoran AGT-001 diubah paksa jadi", rp(tx1.amount), "(tanpa prosedur resmi)")
    print(f"  Sesudah manipulasi -> chain valid: {is_chain_valid(chain)}")
    tx1.amount = 500000  # kembalikan agar skenario berikutnya bersih
    block_A.merkle_root = compute_merkle_root(block_A.transactions)

    section("SKENARIO UJI 2 - Transaksi dari Operator Tidak Terdaftar")
    tx_rogue = Transaction("withdrawal", "AGT-003", 1000000, "TELLER-ROGUE")
    tx_rogue.sign(rogue_private)
    ok, msg = participant_node_verify(tx_rogue, rogue_public)
    status_line(ok, f"Penarikan {rp(tx_rogue.amount)} - operator TELLER-ROGUE", msg)

    section("SKENARIO UJI 3 - Validator Gagal Mencapai Ambang 66%")
    tx6 = make_deposit("AGT-004", 300000, "TELLER-01", teller_private)
    participant_node_verify(tx6, teller_public)

    block_D = Block(index=4, transactions=[tx6])
    link_block(block_D, block_C)
    offline = ["Pengurus Koperasi", "Pengurus Pengawas", "Otoritas Konsorsium"]
    committed, ratio = run_ibft_consensus(block_D, offline_or_byzantine=offline)
    print(f"  Validator offline/tidak setuju: {', '.join(offline)}")
    block_result_line("Block D", committed, ratio, round(ratio * n_validators), n_validators)
    if committed:
        chain.append(block_D)
        observer.sync(chain)
        print(f"  Chain valid setelah Block D -> {auditor.verify_ledger_integrity()}")
    else:
        print("  Block D tidak ditambahkan ke ledger (kuorum validator tidak tercapai)")

    print("\n" + "=" * LINE_WIDTH)