# backend/kafka_consumer_test.py
import json
from kafka import KafkaConsumer

KAFKA_BOOTSTRAP_SERVERS = "localhost:9092"
KAFKA_TOPIC = "network_traffic"

print("Attempting to connect to Kafka...")
try:
    consumer = KafkaConsumer(
        KAFKA_TOPIC,
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        value_deserializer=lambda m: json.loads(m.decode('ascii')),
        auto_offset_reset='earliest', # Start reading from the beginning of the topic
        consumer_timeout_ms=10000 # Stop after 10 seconds if no message is received
    )
    print("✅ Connection successful. Waiting for messages...")

    message_received = False
    for message in consumer:
        print("\n🎉 Message received!")
        print(f"Data: {message.value}")
        message_received = True

    if not message_received:
        print("\n❌ No messages received after 10 seconds.")

except Exception as e:
    print(f"\n🛑 Error connecting to Kafka: {e}")

finally:
    print("Test finished.")