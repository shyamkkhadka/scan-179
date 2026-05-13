# Artifacts of the paper "Detecting and Characterizing Exposed BGP routers" accepted in Network Traffic Measurement and Analysis Conference (TMA) 2026.
## Description of main files
- bgp_scan.py: Creates a BGP-complaint OPEN message to probe IPv4 address space.
- group-asns.py: For connection cease BGP message responders, groups IPs by the “real” router they belong to.
- group-ips-bgp-id-asn.py: For OPEN BGP message responders, group by combinubg BGP ID + ASN + IP location mapping instead of just bgp_id.
- analysis_steps_I.ipynb: First step of data analysis (e.g. honeypot detecting, and categorizing scan responses.)
- analysis_steps_II.ipynb: Ste step of data analysis.
- analysis_steps_III.ipynb: Third step that mainly contains plots of the paper.
