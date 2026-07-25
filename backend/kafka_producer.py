# kafka_producer.py
import json
from kafka import KafkaProducer
import time

producer = KafkaProducer(
    bootstrap_servers='localhost:9092',
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

# A sample attack payload (high values)
attack_data = {
    "flow_duration": 119999872, "tot_fwd_pkts": 100, "tot_bwd_pkts": 200,
    "totlen_fwd_pkts": 50000, "fwd_pkt_len_max": 1500, "fwd_pkt_len_min": 0,
    "fwd_pkt_len_mean": 500, "bwd_pkt_len_max": 3000, "flow_iat_mean": 1000,
    "flow_iat_max": 5000000, "fwd_iat_tot": 120000000
}

print("Sending simulated attack data to Kafka topic 'network_traffic'...")
producer.send('network_traffic', value=attack_data)
producer.flush() # Ensure the message is sent
print("Message sent successfully!")