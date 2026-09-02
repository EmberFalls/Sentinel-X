# Offline mock replay fixture

`mock_recon_demo.pcap` is an explicitly synthetic local UI/integration fixture. It is created by `tools/create_mock_recon_demo.py` and stays ignored by Git under `data/demo/`.

It contains four static Ethernet/IP/TCP flow records only. The generator opens no sockets, transmits no packets, performs no scan, and does not represent a real intrusion, real PCAP, dataset, benchmark, or model-evaluation result.

Its purpose is to exercise this prototype's complete local path: passive parser → incremental flow state → trained Behaviour model → Evidence Gate → alert UI. It must not be used to claim that the model detects real reconnaissance or any real-world attack.

Create it once from the repository root:

```powershell
& 'E:\Python\python.exe' tools/create_mock_recon_demo.py --output data/demo/mock_recon_demo.pcap
```

Then enter `mock_recon_demo.pcap` in the dashboard and select FAST. Use `--replace` only to regenerate that same clearly named mock file. The fixture is intentionally separate from `http.cap`, which remains an unmodified ordinary HTTP replay sample.
