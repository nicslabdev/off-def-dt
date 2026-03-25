import os
import asyncio
import random
import threading
import time
from pymodbus.server.sync import StartTcpServer
from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext
from pymodbus.datastore import ModbusSequentialDataBlock

SLAVE_ID = int(os.getenv("SLAVE_ID", "1"))
PORT = int(os.getenv("MODBUS_PORT", "1502"))

def build_context():
    # Create a data store with 100 holding registers initialized to zero
    store = ModbusSlaveContext(
        di=ModbusSequentialDataBlock(0, [0] * 100),
        co=ModbusSequentialDataBlock(0, [0] * 100),
        hr=ModbusSequentialDataBlock(0, [0] * 100),
        ir=ModbusSequentialDataBlock(0, [0] * 100),
    )
    context = ModbusServerContext(slaves={0x01: store}, single=False)
    return context

def periodic_update_thread(context, stop_event: threading.Event):
    # Update some holding registers periodically to simulate sensor values
    while not stop_event.is_set():
        try:
            slave_id = 1
            # write random values into first 10 holding registers
            new_vals = [random.randint(0, 1000) for _ in range(10)]
            context[slave_id].setValues(3, 0, new_vals)
            print(f"modbus slave {SLAVE_ID} updated HR[0:10] -> {new_vals}")
        except Exception as e:
            print('periodic_update error', e)
        time.sleep(random.uniform(2.0, 6.0))


def run_sync():
    context = build_context()
    stop_event = threading.Event()
    t = threading.Thread(target=periodic_update_thread, args=(context, stop_event), daemon=True)
    t.start()
    print(f"Starting Modbus TCP slave {SLAVE_ID} on 0.0.0.0:{PORT}")
    try:
        # This will block and serve requests
        StartTcpServer(context, address=("0.0.0.0", PORT))
    except KeyboardInterrupt:
        print("Modbus slave stopping")
    finally:
        stop_event.set()
        t.join(timeout=1.0)


if __name__ == '__main__':
    run_sync()
