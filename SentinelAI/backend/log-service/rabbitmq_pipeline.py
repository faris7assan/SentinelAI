"""
SentinelAI — RabbitMQ Log Pipeline Connector
Alternative to Kafka for log ingestion — AMQP protocol
Used when Kafka is unavailable or for lower-volume deployments
"""
import os, json, asyncio
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Callable
import aio_pika
from loguru import logger

RABBITMQ_URL    = os.getenv("RABBITMQ_URL", "amqp://guest:guest@rabbitmq:5672/")
EXCHANGE_NAME   = "sentinelai.logs"
ALERT_EXCHANGE  = "sentinelai.alerts"
LOG_QUEUE       = "sentinelai.logs.queue"
ALERT_QUEUE     = "sentinelai.alerts.queue"
DEAD_LETTER_EX  = "sentinelai.dlx"


class RabbitMQProducer:
    """Async RabbitMQ producer for log and alert events."""

    def __init__(self, url: str = RABBITMQ_URL):
        self.url        = url
        self.connection = None
        self.channel    = None
        self.exchanges  = {}

    async def connect(self):
        try:
            self.connection = await aio_pika.connect_robust(
                self.url,
                reconnect_interval=5,
                fail_fast=False,
            )
            self.channel = await self.connection.channel()
            await self.channel.set_qos(prefetch_count=100)
            # Declare exchanges
            self.exchanges["logs"]   = await self.channel.declare_exchange(
                EXCHANGE_NAME, aio_pika.ExchangeType.TOPIC, durable=True
            )
            self.exchanges["alerts"] = await self.channel.declare_exchange(
                ALERT_EXCHANGE, aio_pika.ExchangeType.TOPIC, durable=True
            )
            # Declare queues with DLX
            logs_queue = await self.channel.declare_queue(
                LOG_QUEUE, durable=True,
                arguments={"x-dead-letter-exchange": DEAD_LETTER_EX, "x-message-ttl": 86400000}
            )
            await logs_queue.bind(self.exchanges["logs"], routing_key="log.#")
            alert_queue = await self.channel.declare_queue(
                ALERT_QUEUE, durable=True,
                arguments={"x-dead-letter-exchange": DEAD_LETTER_EX}
            )
            await alert_queue.bind(self.exchanges["alerts"], routing_key="alert.#")
            logger.info("RabbitMQ producer connected")
        except Exception as e:
            logger.error(f"RabbitMQ connect failed: {e}")

    async def publish_log(self, event: Dict[str, Any]):
        if not self.channel:
            await self.connect()
        severity = event.get("severity", "info")
        routing_key = f"log.{event.get('log_source','unknown')}.{severity}"
        body = json.dumps(event).encode()
        msg = aio_pika.Message(
            body=body,
            delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
            content_type="application/json",
            headers={"source": event.get("log_source",""), "severity": severity},
        )
        await self.exchanges["logs"].publish(msg, routing_key=routing_key)

    async def publish_alert(self, alert: Dict[str, Any]):
        if not self.channel:
            await self.connect()
        severity    = alert.get("severity", "low")
        routing_key = f"alert.{alert.get('detection_type','unknown')}.{severity}"
        body = json.dumps(alert).encode()
        msg = aio_pika.Message(
            body=body,
            delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
            content_type="application/json",
            priority={"critical": 9, "high": 7, "medium": 5, "low": 3}.get(severity, 1),
        )
        await self.exchanges["alerts"].publish(msg, routing_key=routing_key)

    async def close(self):
        if self.connection:
            await self.connection.close()


class RabbitMQConsumer:
    """Async RabbitMQ consumer for detection engine and SOAR."""

    def __init__(self, queue: str, handler: Callable, url: str = RABBITMQ_URL):
        self.url        = url
        self.queue_name = queue
        self.handler    = handler
        self.connection = None

    async def start(self):
        self.connection = await aio_pika.connect_robust(self.url, reconnect_interval=5)
        channel = await self.connection.channel()
        await channel.set_qos(prefetch_count=10)
        queue   = await channel.declare_queue(self.queue_name, durable=True, passive=True)

        async def process(message: aio_pika.IncomingMessage):
            async with message.process(requeue=True):
                try:
                    event = json.loads(message.body.decode())
                    await self.handler(event)
                except Exception as e:
                    logger.error(f"Message processing failed: {e}")

        await queue.consume(process)
        logger.info(f"RabbitMQ consumer started on queue '{self.queue_name}'")

    async def stop(self):
        if self.connection:
            await self.connection.close()


# ─── Redis Streams Pipeline ──────────────────────────────────
class RedisStreamsPipeline:
    """
    Redis Streams as an alternative message queue.
    Lighter than Kafka/RabbitMQ for small-scale deployments.
    """
    import aioredis

    def __init__(self, redis_url: str = os.getenv("REDIS_URL", "redis://redis:6379/0")):
        self.redis_url    = redis_url
        self.redis        = None
        self.LOG_STREAM   = "sentinelai:logs"
        self.ALERT_STREAM = "sentinelai:alerts"
        self.MAX_LEN      = 100_000

    async def connect(self):
        import aioredis
        self.redis = await aioredis.from_url(self.redis_url, decode_responses=True)
        logger.info("Redis Streams pipeline connected")

    async def publish_log(self, event: Dict[str, Any]):
        fields = {k: str(v) for k, v in event.items() if v is not None}
        await self.redis.xadd(self.LOG_STREAM, fields, maxlen=self.MAX_LEN, approximate=True)

    async def publish_alert(self, alert: Dict[str, Any]):
        fields = {k: str(v) for k, v in alert.items() if v is not None}
        await self.redis.xadd(self.ALERT_STREAM, fields, maxlen=50_000, approximate=True)

    async def consume_logs(self, group: str, consumer: str, handler: Callable, last_id: str = ">"):
        """Consumer group-based log consumption."""
        try:
            await self.redis.xgroup_create(self.LOG_STREAM, group, mkstream=True)
        except Exception:
            pass  # Group already exists
        while True:
            messages = await self.redis.xreadgroup(
                group, consumer, {self.LOG_STREAM: last_id}, count=100, block=1000
            )
            for stream, msgs in messages:
                for msg_id, fields in msgs:
                    try:
                        await handler(fields)
                        await self.redis.xack(self.LOG_STREAM, group, msg_id)
                    except Exception as e:
                        logger.error(f"Stream consumer error: {e}")

    async def consume_alerts(self, group: str, consumer: str, handler: Callable):
        """Consume alert stream for SOAR processing."""
        try:
            await self.redis.xgroup_create(self.ALERT_STREAM, group, mkstream=True)
        except Exception:
            pass
        while True:
            messages = await self.redis.xreadgroup(
                group, consumer, {self.ALERT_STREAM: ">"}, count=50, block=1000
            )
            for stream, msgs in messages:
                for msg_id, fields in msgs:
                    try:
                        await handler(fields)
                        await self.redis.xack(self.ALERT_STREAM, group, msg_id)
                    except Exception as e:
                        logger.error(f"Alert stream error: {e}")

    async def lag(self) -> Dict[str, int]:
        """Get consumer lag for monitoring."""
        try:
            log_info   = await self.redis.xinfo_groups(self.LOG_STREAM)
            alert_info = await self.redis.xinfo_groups(self.ALERT_STREAM)
            return {
                "log_lag":   sum(g.get("lag", 0) for g in log_info),
                "alert_lag": sum(g.get("lag", 0) for g in alert_info),
            }
        except Exception:
            return {"log_lag": 0, "alert_lag": 0}
