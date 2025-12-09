# Encrypted Messaging CLI


See the report document for details. To run:


1. python3 -m venv .venv && source .venv/bin/activate
2. pip install -r requirements.txt
3. In terminal A: python peer.py --mode server --port 5000
4. In terminal B: python peer.py --mode client --host 127.0.0.1 --port 5000


Type messages and press enter to send. Ctrl-C to quit.
