import json
import os

from kafka import KafkaConsumer


KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9094")
KAFKA_TOPIC = os.getenv("RAW_NETWORK_EVENTS_TOPIC", "raw.network-events")


print(f"Attempting to consume from {KAFKA_TOPIC} on {KAFKA_BOOTSTRAP_SERVERS}...")
consumer = KafkaConsumer(
    KAFKA_TOPIC,
    bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
    value_deserializer=lambda value: json.loads(value.decode("utf-8")),
    auto_offset_reset="earliest",
    group_id="ndr-consumer-smoke-test",
    consumer_timeout_ms=10000,
)

message_received = False
try:
    for message in consumer:
        print("Message received:")
        print(json.dumps(message.value, indent=2))
        message_received = True
    if not message_received:
        print("No messages received after 10 seconds.")
finally:
    consumer.close()
