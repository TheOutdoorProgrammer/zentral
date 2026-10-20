import logging
import random
import time
import threading
from django.utils.functional import SimpleLazyObject
import httpx
from zentral import telemetry
from zentral.utils.ssl import create_client_ssl_context
from .events import build_mdm_device_notification_event
from .models import PushCertificate


logger = logging.getLogger('zentral.contrib.mdm.apns')


# client


class APNSClient:
    apns_production_base_url = "https://api.push.apple.com"
    timeout = 5
    max_retries = 2

    def __init__(self, topic, not_after, cert, privkey):
        self.topic = topic
        self.not_after = not_after
        ssl_context = create_client_ssl_context(cert, privkey)
        self.client = httpx.Client(
            base_url=self.apns_production_base_url,
            http2=True,
            verify=ssl_context,
            timeout=self.timeout
        )

    @classmethod
    def from_push_certificate(cls, push_certificate):
        return cls(
            push_certificate.topic,
            push_certificate.not_after,
            push_certificate.certificate,
            push_certificate.get_private_key(),
        )

    def send_notification(self, token, push_magic, priority=10, expiration_seconds=3600):
        with telemetry.operation("job.run", attributes={"messaging.system": "apns"}) as span:
            span.update_name("mdm.apns.notification")
            success, error = self._send_notification(token, push_magic, priority, expiration_seconds, span)
            telemetry.event("job.run", "success" if success else "failure", error=error if not success else None)
            return success

    def _send_notification(self, token, push_magic, priority, expiration_seconds, span):
        if isinstance(token, (bytes, memoryview)):
            token = token.hex()

        url = f"/3/device/{token}"
        payload = {"mdm": push_magic}
        headers = {"apns-push-type": "mdm",
                   "apns-expiration": str(int(time.time()) + expiration_seconds),
                   "apns-priority": str(priority),
                   "apns-topic": self.topic}

        success = False
        last_error = None

        for retry_num in range(self.max_retries + 1):
            try:
                r = self.client.post(url, json=payload, headers=headers)
            except Exception as error:
                if isinstance(error, httpx.TimeoutException):
                    last_error = TimeoutError()
                elif isinstance(error, httpx.NetworkError):
                    last_error = ConnectionError()
                else:
                    last_error = error
            else:
                last_error = None
                span.set_attribute("http.response.status_code", r.status_code)
                if r.status_code == httpx.codes.OK:
                    success = True
                    break
                if r.status_code < 500:
                    # only retry 500s
                    break
            sleep_time = random.random() * 2 ** retry_num
            logger.warning("APNs request retry")
            time.sleep(sleep_time)

        return success, last_error


# client cache


class APNSClientCache:
    def __init__(self):
        self._clients = {}
        self._lock = threading.Lock()

    def get_or_create(self, topic, not_after, push_cert=None):
        assert push_cert is None or (push_cert.topic == topic and push_cert.not_after == not_after)
        with self._lock:
            client = self._clients.get(topic)
            if not client or client.not_after < not_after:
                if push_cert is None:
                    try:
                        push_cert = PushCertificate.objects.get(topic=topic)
                    except PushCertificate.DoesNotExist:
                        logger.warning("APNs push certificate unavailable")
                        return
                client = APNSClient.from_push_certificate(push_cert)
                self._clients[topic] = client
            return client

    def get_or_create_with_push_cert(self, push_cert):
        return self.get_or_create(push_cert.topic, push_cert.not_after, push_cert)


apns_client_cache = SimpleLazyObject(lambda: APNSClientCache())


# utils


def _send_target_notification(enrolled_device, token, user_id=None, priority=10, expiration_seconds=3600,
                              request=None):
    if not enrolled_device.can_be_poked() or not token:
        logger.error("APNs target unavailable")
        return False, None
    client = apns_client_cache.get_or_create_with_push_cert(enrolled_device.push_certificate)
    success = client.send_notification(token, enrolled_device.push_magic, priority, expiration_seconds)
    return success, build_mdm_device_notification_event(
        enrolled_device.serial_number, enrolled_device.udid,
        priority, expiration_seconds,
        success, user_id, request
    )


def send_enrolled_user_notification(enrolled_user, post_event=True, request=None):
    success, event = _send_target_notification(
        enrolled_user.enrolled_device, enrolled_user.token, enrolled_user.user_id, request=request
    )
    if post_event and event:
        event.post()
    return success, event


def send_enrolled_device_notification(enrolled_device, post_event=True, request=None):
    success, event = _send_target_notification(
        enrolled_device, enrolled_device.token, request=request
    )
    if post_event and event:
        event.post()
    return success, event
