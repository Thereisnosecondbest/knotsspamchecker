# Bitcoin Knots Spam Filter Checker
# Copyright (C) 2024 Thereisnosecondbest
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.


import streamlit as st
from bitcoin.core import CTransaction, CScript
from bitcoin.core.script import OP_RETURN, OP_CHECKSIG, OP_DUP, OP_EQUALVERIFY, OP_HASH160
from bitcoin.wallet import CBitcoinAddress
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
from decimal import Decimal


# 비트코인 RPC 설정
RPC_USER = 'btcnode'
RPC_PASSWORD = 'btcnode'
RPC_HOST = '127.0.0.1'
RPC_PORT = '8332'

# RPC 연결 설정
rpc_connection = AuthServiceProxy(f"http://{RPC_USER}:{RPC_PASSWORD}@{RPC_HOST}:{RPC_PORT}")

# 설정 상수들 (Knots 정책 기반)
MAX_STANDARD_TX_WEIGHT = 400000
MAX_STANDARD_SCRIPTSIG_SIZE = 1650
DUST_RELAY_TX_FEE = 3000  # satoshis per kB
DEFAULT_BYTES_PER_SIGOP = 20
MAX_UNCONFIRMED_ANCESTORS = 25
MAX_ANCESTOR_SIZE_KB = 101
MAX_DESCENDANT_COUNT = 25
MAX_DESCENDANT_SIZE_KB = 101
MIN_BYTES_PER_SIGOP = 20  # 최소 바이트 수 per SigOp

def is_standard_script(script):
    """Check if a script is one of the standard types (P2PKH, P2SH, P2WPKH, etc.)."""
    # P2PKH: OP_DUP OP_HASH160 <PubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
    if (len(script) == 25 and
        script[0] == OP_DUP and
        script[1] == OP_HASH160 and
        script[2] == 0x14 and  # 0x14 is the length of the PubKeyHash (20 bytes)
        script[23] == OP_EQUALVERIFY and
        script[24] == OP_CHECKSIG):
        return True

    # P2SH: OP_HASH160 <ScriptHash> OP_EQUAL
    if (len(script) == 23 and
        script[0] == OP_HASH160 and
        script[1] == 0x14 and  # 0x14 is the length of the ScriptHash (20 bytes)
        script[22] == OP_EQUALVERIFY):
        return True

    # P2WPKH and P2WSH are more complex and would require additional checks.
    
    # OP_RETURN (Data-carrying output)
    if len(script) > 0 and script[0] == OP_RETURN:
        return True

    return False

def is_dust(txout, dust_relay_fee):
    size = len(txout.serialize())
    dust_threshold = (size * dust_relay_fee) / 1000
    return txout.nValue < dust_threshold

def get_transaction_fee(tx):
    total_input_value = 0
    for txin in tx.vin:
        try:
            raw_prev_tx = rpc_connection.getrawtransaction(txin.prevout.hash.hex(), True)
            prev_tx = CTransaction.deserialize(bytes.fromhex(raw_prev_tx['hex']))
            total_input_value += prev_tx.vout[txin.prevout.n].nValue
        except JSONRPCException as e:
            print(f"Error fetching previous transaction: {e}")
            return None

    total_output_value = sum(txout.nValue for txout in tx.vout)
    return total_input_value - total_output_value

def get_ancestor_count(txid):
    try:
        mempool_entry = rpc_connection.getmempoolentry(txid)
        return mempool_entry['ancestorcount']
    except JSONRPCException as e:
        print(f"Error fetching ancestor count: {e}")
        return 0

def get_ancestor_size(txid):
    try:
        mempool_entry = rpc_connection.getmempoolentry(txid)
        return mempool_entry['ancestorsize']
    except JSONRPCException as e:
        print(f"Error fetching ancestor size: {e}")
        return 0

def get_descendant_count(txid):
    try:
        mempool_entry = rpc_connection.getmempoolentry(txid)
        return mempool_entry['descendantcount']
    except JSONRPCException as e:
        print(f"Error fetching descendant count: {e}")
        return 0

def get_descendant_size(txid):
    try:
        mempool_entry = rpc_connection.getmempoolentry(txid)
        return mempool_entry['descendantsize']
    except JSONRPCException as e:
        print(f"Error fetching descendant size: {e}")
        return 0

def contains_non_bitcoin_protocol(tx):
    """Check if the transaction contains data associated with non-Bitcoin token/asset overlay protocols."""
    for txout in tx.vout:
        script = CScript(txout.scriptPubKey)
        if script.is_opreturn():
            # 여기에 자산 오버레이 프로토콜과 관련된 데이터 패턴을 추가로 확인해야 함
            if b"Omni" in script or b"RSK" in script:  # 예제: OmniLayer 또는 RSK와 관련된 패턴
                print("Rejected: Transaction contains non-Bitcoin token/asset overlay protocol")
                return True
    return False

def check_standard_tx(tx):
    # 1. Unrecognised receiver scripts
    for txout in tx.vout:
        script = CScript(txout.scriptPubKey)
        if not is_standard_script(script):
            print("Rejected: Unrecognised receiver script")
            return False

    # 2. Parasite transactions (기본적으로 거부)
    reject_parasites = True
    if reject_parasites:
        print("Rejected: Parasite transaction")
        return False

    # 3. Non-Bitcoin token/asset overlay protocols
    if contains_non_bitcoin_protocol(tx):
        return False

    # 4. 수수료율 검사
    fee = get_transaction_fee(tx)
    if fee is None:
        return False
    weight = tx.get_weight()
    fee_rate = Decimal(fee) / (weight / 4)  # satoshis per kB
    if fee_rate < 0.00001000:
        print("Rejected: Low fee rate")
        return False

    # 5. SigOp 최소 크기 처리
    total_sigops = sum(len(txin.scriptSig) // DEFAULT_BYTES_PER_SIGOP for txin in tx.vin)
    adjusted_vsize = tx.get_vsize() + (total_sigops * DEFAULT_BYTES_PER_SIGOP)
    if adjusted_vsize > MAX_STANDARD_TX_WEIGHT:
        print("Rejected: Adjusted vsize exceeds weight limit due to SigOps")
        return False

    # 6. SigOp 당 최소 바이트 수 검사
    for txin in tx.vin:
        if len(txin.scriptSig) < MIN_BYTES_PER_SIGOP:
            print("Rejected: Fewer than minimum bytes per potentially-executed SigOp")
            return False

    # 7. 조상 트랜잭션 수 검사
    ancestor_count = get_ancestor_count(tx.GetHash().hex())
    if ancestor_count >= MAX_UNCONFIRMED_ANCESTORS:
        print("Rejected: Too many unconfirmed ancestors")
        return False

    # 8. 조상 트랜잭션 크기 검사
    ancestor_size = get_ancestor_size(tx.GetHash().hex())
    if ancestor_size > MAX_ANCESTOR_SIZE_KB * 1000:
        print("Rejected: Ancestor size too large")
        return False

    # 9. 후손 트랜잭션 수 검사
    descendant_count = get_descendant_count(tx.GetHash().hex())
    if descendant_count >= MAX_DESCENDANT_COUNT:
        print("Rejected: Too many unconfirmed descendants")
        return False

    # 10. 후손 트랜잭션 크기 검사
    descendant_size = get_descendant_size(tx.GetHash().hex())
    if descendant_size > MAX_DESCENDANT_SIZE_KB * 1000:
        print("Rejected: Descendant size too large")
        return False

    # 11. Bare/exposed public keys
    for txout in tx.vout:
        script = CScript(txout.scriptPubKey)
        if script.is_bare_pubkey():
            print("Rejected: Bare/exposed public key")
            return False

    # 12. Bare/exposed multisig scripts
    for txout in tx.vout:
        script = CScript(txout.scriptPubKey)
        if script.is_bare_multisig():
            print("Rejected: Bare/exposed multisig script")
            return False

    # 13. 스마트 컨트랙트 코드 크기 제한
    for txout in tx.vout:
        if len(txout.scriptPubKey) > MAX_STANDARD_SCRIPTSIG_SIZE:
            print("Rejected: Smart contract code too large")
            return False

    return True


# Streamlit 웹 앱
st.title("Bitcoin Knots Spam Filter Checker")

tx_hex = st.text_area("Enter the transaction hex", height=150)
if st.button("Check Transaction"):
    try:
        tx = CTransaction.deserialize(bytes.fromhex(tx_hex.strip()))
        if check_standard_tx(tx):
            st.success("Transaction is standard and passes all filters")
        else:
            st.error("Transaction does not pass one or more standard checks")
    except Exception as e:
        st.error(f"Error processing transaction: {e}")
