from django.apps import AppConfig
import sys


class TrustmonitorConfig(AppConfig):
    name = 'trust_monitor'

    def ready(self):
        if 'runserver' not in sys.argv:
            return True

        from trust_monitor.verifier.structs import InstantiateDigest
        InstantiateDigest.instantiate_known_digest()
