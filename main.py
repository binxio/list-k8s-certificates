from kubernetes import client, config
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import base64
import colorama
from humanize import naturaldelta
import logging
import os

config.load_kube_config()

colorama.init(autoreset=True)


def certificate_from_secret(secret: client.V1Secret) -> x509.Certificate:
    return x509.load_pem_x509_certificate(
        base64.b64decode(secret.data["tls.crt"]), default_backend()
    )


def list_certificates() -> [client.V1Secret]:
    result = []
    v1 = client.CoreV1Api()
    secrets = v1.list_secret_for_all_namespaces()

    return sorted(
        filter(lambda s: s.type == "kubernetes.io/tls", secrets.items),
        key=lambda s: certificate_from_secret(s).not_valid_after,
    )


def report_expiration(secrets: [client.V1Secret]):
    for secret in secrets:
        certificate = certificate_from_secret(secret)
        expires_on = certificate.not_valid_after
        time_left = expires_on - datetime.today()
        ago = naturaldelta(time_left)
        if time_left < timedelta(days=0):
            logging.error(
                f"Certificate {secret.metadata.namespace}/{secret.metadata.name} expired {ago} ago  on {expires_on}"
            )
        elif time_left < timedelta(days=5):
            logging.warning(
                f"Certificate {secret.metadata.namespace}/{secret.metadata.name} about to expire in {ago} on {expires_on}"
            )
        else:
            logging.info(
                f"Certificate {secret.metadata.namespace}/{secret.metadata.name} valid for {ago} until {expires_on}"
            )


if __name__ == "__main__":
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"), format="%(levelname)s: %(message)s"
    )
    report_expiration(reversed(list_certificates()))
