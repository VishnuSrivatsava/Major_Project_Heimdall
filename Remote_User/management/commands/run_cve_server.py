# management/commands/run_cve_server.py
from django.core.management.base import BaseCommand
from cve_server import CVEServer # Adjusted import

class Command(BaseCommand):
    help = 'Runs the CVE data collection server'

    def handle(self, *args, **options):
        self.stdout.write('Starting CVE server...')
        server = CVEServer()
        server.start()