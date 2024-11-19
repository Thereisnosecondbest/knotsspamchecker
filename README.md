# Bitcoin Knots Spam Filter Checker
This project is a simple web application built with Streamlit to check if a Bitcoin transaction complies with the spam filter rules implemented in Bitcoin Knots. It provides an easy-to-use interface for validating raw Bitcoin transactions against common spam filters.

## Features
- **Standard Script Checking**: Ensures that the transaction uses recognized script types (e.g., P2PKH, P2SH, OP_RETURN).
- **Fee Rate Validation**: Verifies that the transaction fee rate is above the minimum threshold.
- **Dust Output Detection**: Identifies dust outputs that are uneconomical to spend.
- **Non-Bitcoin Protocol Detection**: Flags transactions that may be associated with non-Bitcoin token or asset overlay protocols.

## Requirements
- Python 3.7+
- Streamlit
- python-bitcoinlib
- python-bitcoinrpc

## Installation
1. Clone the repository:
   git clone https://github.com/Thereisnosecondbest/knotsspamchecker.git
   cd knotsspamchecker

3. Install the dependencies:
   pip install -r requirements.txt

## Usage
1. Run the Streamlit app:
   streamlit run check_knots_spam.py
2. Open the link provided in the terminal to access the web app.
3. Enter a raw Bitcoin transaction (tx_hex) and click "Check Transaction" to see the results.

## How It Works
The app uses python-bitcoinlib to parse and analyze Bitcoin transactions. It communicates with a Bitcoin node using python-bitcoinrpc to fetch additional data, such as previous transaction outputs and mempool details. The app then checks the transaction against various spam filter rules:

Standard Scripts: Validates that the scripts used in the transaction are of known types.
Fee Rate: Ensures the transaction has a sufficient fee rate.
Dust Outputs: Detects outputs that are considered uneconomical to spend.
Non-Bitcoin Protocols: Identifies potential non-Bitcoin-related protocols.
...

