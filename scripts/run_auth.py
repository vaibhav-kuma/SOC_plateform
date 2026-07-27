import uvicorn
uvicorn.run('services.auth_service.main:app', host='0.0.0.0', port=8002, log_level='info')
