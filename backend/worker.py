import json
import signal
import sys
import threading
from typing import Any, Dict, Iterable

from kafka import KafkaConsumer, KafkaProducer

from .config import settings
from .database import SessionLocal
from .migrations.runner import run_migrations
from .pipeline import persist_dead_letter, process_payload
from .serializers import detection_to_dict, event_to_dict


class DetectionWorker:
    def __init__(self):
        self.stop_event = threading.Event()
        self.consumer = None
        self.producer = None

    def start(self):
        if settings.auto_migrate:
            run_migrations()
        topics = list(dict.fromkeys([settings.raw_topic, settings.legacy_topic]))
        self.consumer = KafkaConsumer(
            *topics,
            bootstrap_servers=settings.kafka_bootstrap_servers,
            auto_offset_reset="earliest",
            enable_auto_commit=False,
            group_id=settings.worker_group_id,
            consumer_timeout_ms=1000,
            value_deserializer=lambda value: value.decode("utf-8"),
        )
        self.producer = KafkaProducer(
            bootstrap_servers=settings.kafka_bootstrap_servers,
            value_serializer=lambda value: json.dumps(value, default=str).encode("utf-8"),
        )
        print(
            f"Detection worker consuming {topics} as group '{settings.worker_group_id}' "
            f"from {settings.kafka_bootstrap_servers}"
        )
        while not self.stop_event.is_set():
            for message in self.consumer:
                if self.stop_event.is_set():
                    break
                self._handle_message(message)
        self.close()

    def _handle_message(self, message):
        payload: Dict[str, Any]
        try:
            payload = json.loads(message.value)
            if not isinstance(payload, dict):
                raise ValueError("Kafka event value must be a JSON object")
        except Exception as exc:
            self._dead_letter(
                payload={"raw": message.value},
                error=f"Invalid JSON message: {exc}",
                message=message,
            )
            self.consumer.commit()
            return

        db = SessionLocal()
        try:
            result = process_payload(
                payload,
                db,
                raw_reference=f"kafka:{message.topic}:{message.partition}:{message.offset}",
            )
            db.commit()
            self._produce(settings.normalized_topic, event_to_dict(result["event"]))
            self._produce(settings.detections_topic, detection_to_dict(result["detection"]))
            self.consumer.commit()
        except Exception as exc:
            db.rollback()
            self._dead_letter(payload=payload, error=str(exc), message=message)
            self.consumer.commit()
        finally:
            db.close()

    def _produce(self, topic: str, payload: Dict[str, Any]):
        if self.producer:
            self.producer.send(topic, value=payload)
            self.producer.flush(timeout=5)

    def _dead_letter(self, payload: Dict[str, Any], error: str, message):
        db = SessionLocal()
        try:
            persist_dead_letter(
                db,
                payload=payload,
                error=error,
                event_key=payload.get("event_id") if isinstance(payload, dict) else None,
                topic=getattr(message, "topic", None),
                partition=getattr(message, "partition", None),
                offset=getattr(message, "offset", None),
            )
            db.commit()
            self._produce(
                settings.dead_letter_topic,
                {
                    "payload": payload,
                    "error": error,
                    "topic": getattr(message, "topic", None),
                    "partition": getattr(message, "partition", None),
                    "offset": getattr(message, "offset", None),
                },
            )
        except Exception as exc:
            db.rollback()
            print(f"Failed to persist dead-letter event: {exc}", file=sys.stderr)
        finally:
            db.close()

    def stop(self, *_args):
        self.stop_event.set()

    def close(self):
        if self.consumer:
            self.consumer.close()
        if self.producer:
            self.producer.flush(timeout=5)
            self.producer.close()
        print("Detection worker stopped.")


def main():
    worker = DetectionWorker()
    signal.signal(signal.SIGINT, worker.stop)
    signal.signal(signal.SIGTERM, worker.stop)
    worker.start()


if __name__ == "__main__":
    main()
