# For OPEN BGP message responders:
# Group IPs by the “real” router they belong to, even if multiple ASNs share 
# the same bgp_id. To do this properly, we combine BGP ID + ASN + IP location mapping instead of just bgp_id.
import pandas as pd
import ipaddress
import numpy as np

path = "/routersecurity/"

#import pandas as pd
import ipaddress

# Load files
# bgp_file = path + "results/bgp_scan_results_2_dec.csv"

bgp_file = path + "results/open_only_02_feb_bonaire.csv"

output_file = path + "results/open_only_02_feb_bonaire_router_mapping.csv" # Based on ASN obtained from BGP OPEN message.

# Load BGP file (only target_ip and bgp_id)
df_bgp = pd.read_csv(bgp_file, usecols=["target_ip", "bgp_id", "asn"])

# Keep only rows where bgp_id is not empty or NaN
df_bgp = df_bgp[df_bgp["bgp_id"].notna() & (df_bgp["bgp_id"] != "")]

# Keep only rows where asn is not empty or NaN
df_bgp = df_bgp[df_bgp["asn"].notna() & (df_bgp["asn"] != "")]
df_bgp["asn"] = df_bgp["asn"].astype(int).astype(str)

# Keep only IPv4 addresses
df_bgp = df_bgp[df_bgp["target_ip"].str.contains(r"^\d+\.\d+\.\d+\.\d+$")]

# Create router_key
df_bgp["router_key"] = df_bgp.apply(
    lambda row: f"{row['bgp_id']}_{row['asn']}" if pd.notna(row['asn']) else f"{row['bgp_id']}_ASnan",
    axis=1
)

# Save the result
df_bgp[["target_ip", "bgp_id", "asn", "router_key"]].to_csv(output_file, index=False)

print(f"Saved results to {output_file}")
