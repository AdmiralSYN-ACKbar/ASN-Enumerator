# Admiral SYN-ACKbar's ASN Enumerator
This Python script provides a simple GUI for looking up Autonomous System Numbers (ASNs) and their associated IP prefixes. It uses the BGPView API to retrieve the data and displays it in a user-friendly format.

## Features

- Lookup ASN details for a given IP address
- Enumerate IP prefixes for a given ASN
- Search for ASNs by organization name
- Write output to a CSV file

## Why is this a useful tool?

Knowing the ASN associated with a particular IP address can provide valuable information about the network where the IP address resides. This can be useful for network routing, security investigations and troubleshooting.

## How to Use

1. Run the script. This will open a GUI.
2. To lookup the ASN for a given IP address, enter the IP address in the "IP to ASN" field and click "Lookup".
3. To enumerate the IP prefixes for a given ASN, enter the ASN in the "ASN to IP" field and click "Enumerate".
4. The output will be displayed in the output box.
5. To write the output to a CSV file, enter the file path in the "Write Output" field and click "Write". You can also click "Browse" to select a file.

## Requirements

- Python 3
- `requests` library
- `tkinter` library
- `ipaddress` library
- `datetime` library

## Screenshots

<p float="left">
  <img src="/output1.png" /> 
  <img src="/output2.png" /> 
</p>
