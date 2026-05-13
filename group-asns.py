# For connection cease BGP message responders only (category2_1M.csv) as opposite of code group-ips-bgp-id-asn.py:
# Group IPs by the “real” router they belong to, even if multiple ASNs share 
# the same bgp_id. To do this properly, we combine BGP ID + ASN + IP location mapping instead of just bgp_id.
import pandas as pd
import ipaddress
import numpy as np

path = "/routersecurity/"

#import pandas as pd
import ipaddress

# Load files
bgp_file = path + "results/notification_only_02_feb_bonaire.csv"
asn_file = path + "2026-02-02_country_asn.csv"
output_file = path + "results/notification_only_02_feb_bonaire_router_mapping.csv"

# Load BGP file (only target_ip and bgp_id)
df_bgp = pd.read_csv(bgp_file, usecols=["target_ip"])

# Load ASN file (all columns)
df_asn = pd.read_csv(asn_file)

# Keep only IPv4 in ASN file
df_asn = df_asn[df_asn["start_ip"].str.contains(r"^\d+\.\d+\.\d+\.\d+$")]

# Convert IPs to integers for fast range lookup
df_asn["start_int"] = df_asn["start_ip"].apply(lambda x: int(ipaddress.IPv4Address(x)))
df_asn["end_int"] = df_asn["end_ip"].apply(lambda x: int(ipaddress.IPv4Address(x)))
df_bgp["ip_int"] = df_bgp["target_ip"].apply(lambda x: int(ipaddress.IPv4Address(x)))

# Sort ASN dataframe for efficient search
df_asn = df_asn.sort_values("start_int").reset_index(drop=True)

# Function to map IP to ASN
def map_asn(ip_int, asn_df):
    # Binary search for efficiency
    left, right = 0, len(asn_df) - 1
    while left <= right:
        mid = (left + right) // 2
        if asn_df.loc[mid, "start_int"] <= ip_int <= asn_df.loc[mid, "end_int"]:
            return asn_df.loc[mid, "asn"]
        elif ip_int < asn_df.loc[mid, "start_int"]:
            right = mid - 1
        else:
            left = mid + 1
    return None  # Not found

# Map ASN (vectorized would be faster with interval tree, but binary search works fine for medium data)
df_bgp["asn"] = df_bgp["ip_int"].apply(lambda x: map_asn(x, df_asn))

# Save the result
df_bgp[["target_ip", "asn"]].to_csv(output_file, index=False)

print(f"Saved results to {output_file}")
