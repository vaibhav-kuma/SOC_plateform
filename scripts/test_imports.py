"""Test that all service modules import correctly."""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))
os.environ['LOG_LEVEL'] = 'ERROR'
os.environ['DATABASE_URL'] = 'postgresql+asyncpg://socuser:socpass@localhost:5432/socplatform'
os.environ['REDIS_URL'] = 'redis://localhost:6379/0'
os.environ['JWT_SECRET_KEY'] = 'test-key'
os.environ['ELASTICSEARCH_HOSTS'] = '["http://localhost:9200"]'
os.environ['KAFKA_BOOTSTRAP_SERVERS'] = 'localhost:9092'

def test_import(module_name, label):
    try:
        __import__(module_name, fromlist=['app'])
        print(f'  OK {label}')
        return True
    except Exception as e:
        print(f'  FAIL {label}: {e}')
        return False

print('Testing backend module imports...\n')

# Core modules
print('Core:')
test_import('core.config', 'config')
test_import('core.database', 'database')
test_import('core.security', 'security')
test_import('core.redis', 'redis')
test_import('core.elastic', 'elastic')
test_import('core.kafka', 'kafka')

print('\nCommon:')
test_import('common.models.base', 'models.base')

print('\nServices (API import only):')
test_import('services.auth_service.main', 'Auth Service')
test_import('services.asset_discovery.main', 'Asset Discovery')
test_import('services.vuln_scanner.main', 'Vuln Scanner')
test_import('services.edr_service.main', 'EDR Service')
test_import('services.ndr_service.main', 'NDR Service')
test_import('services.threat_intel.main', 'Threat Intel')
test_import('services.incident_response.main', 'Incident Response')
test_import('services.mitre_mapper.main', 'MITRE Mapper')
test_import('services.cloud_security.main', 'Cloud Security')
test_import('services.ai_copilot.main', 'AI Copilot')

print('\nDone.')
