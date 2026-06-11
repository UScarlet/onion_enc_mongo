import asyncio
import time

async def mice():
    print("[mice] Начал пищать...")
    await asyncio.sleep(5)  # Имитируем долгую задачу
    print("[mice] pipipip")
    
async def mice2():
    print("[mice2] Начал пищать...")
    await asyncio.sleep(3)  # Имитируем быструю задачу
    print("[mice2] pipipip222222")

async def call_mice():
    start_time = time.time()
    
    # asyncio.gather запускает обе функции ОДНОВРЕМЕННО
    await asyncio.gather(
        mice(),
        mice2()
    )
    
    end_time = time.time()
    print(f"\nВсе задачи выполнены за {end_time - start_time:.2f} секунд!")

if __name__ == '__main__':
    asyncio.run(call_mice())