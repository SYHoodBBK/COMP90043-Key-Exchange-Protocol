import asyncio
from X3DH.Alice import get_alice_info
from X3DH.Bob import get_bob_info

async def main():
    bob_info = await get_bob_info()
    print(bob_info)

if __name__ == "__main__":
    asyncio.run(main())
