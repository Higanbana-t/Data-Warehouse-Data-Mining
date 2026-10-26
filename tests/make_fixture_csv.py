"""Minimal GeneratedLabelledFlows rows for API simulator tests."""

HEADER = (
    "Flow ID,Source IP,Source Port,Destination IP,Destination Port,Protocol,"
    "Timestamp,Flow Duration,Total Fwd Packets,Total Backward Packets,"
    "Flow Bytes/s,Flow Packets/s,Label"
)

TEMPLATE = (
    "192.168.10.12-192.168.10.5-49188-80-6,192.168.10.12,49188,"
    "192.168.10.5,80,6,7/7/2017 1:00,123456,3,4,1000.5,2.5,BENIGN"
)
