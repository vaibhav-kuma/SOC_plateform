import asyncio, asyncpg
async def t():
    try:
        conn = await asyncpg.connect(user='socuser', password='socpass', host='127.0.0.1', port=5434, database='socplatform')
        print('Connected OK')
        await conn.close()
    except Exception as e:
        print(f'Failed: {e}')
asyncio.run(t())
