import json
import os

from kafka import KafkaProducer


KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9094")
KAFKA_TOPIC = os.getenv("RAW_NETWORK_EVENTS_TOPIC", "raw.network-events")


producer = KafkaProducer(
    bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
    value_serializer=lambda value: json.dumps(value).encode("utf-8"),
)

synthetic_attack_event = {
    "event_id": "demo-synthetic-high-volume-001",
    "timestamp": "2026-01-01T00:00:00Z",
    "source_ip": "10.10.5.23",
    "source_port": 51515,
    "destination_ip": "203.0.113.66",
    "destination_port": 443,
    "protocol": "TCP",
    "flow_duration": 119999872,
    "tot_fwd_pkts": 100,
    "tot_bwd_pkts": 200,
    "totlen_fwd_pkts": 50000,
    "fwd_pkt_len_max": 1500,
    "fwd_pkt_len_min": 0,
    "fwd_pkt_len_mean": 500,
    "bwd_pkt_len_max": 3000,
    "flow_iat_mean": 1000,
    "flow_iat_max": 5000000,
    "fwd_iat_tot": 120000000,
}

print("Authorized lab/demo use only. Sending one synthetic event.")
print(f"Broker: {KAFKA_BOOTSTRAP_SERVERS}")
print(f"Topic: {KAFKA_TOPIC}")
producer.send(KAFKA_TOPIC, value=synthetic_attack_event)
producer.flush()
producer.close()
print("Synthetic event sent successfully.")
