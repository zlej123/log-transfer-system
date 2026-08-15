#!/usr/bin/env python3
"""Opaque TCP relay with optional byte-drop, throttling and concurrency."""
import selectors
import socket
import sys
import threading
import time

listen_port = int(sys.argv[1])
upstream_port = int(sys.argv[2])
drop_after = int(sys.argv[3])
delay_ms = int(sys.argv[4]) if len(sys.argv) > 4 else 0
connection_count = int(sys.argv[5]) if len(sys.argv) > 5 else 1


def relay(client: socket.socket) -> None:
    upstream = socket.create_connection(("127.0.0.1", upstream_port))
    with client, upstream:
        client.setblocking(False)
        upstream.setblocking(False)
        selector = selectors.DefaultSelector()
        selector.register(client, selectors.EVENT_READ, (client, upstream, True))
        selector.register(upstream, selectors.EVENT_READ, (upstream, client, False))
        forwarded = 0
        while True:
            events = selector.select(timeout=10)
            if not events:
                return
            for key, _ in events:
                source, destination, counted = key.data
                try:
                    data = source.recv(16384)
                except BlockingIOError:
                    continue
                if not data:
                    return
                view = memoryview(data)
                while view:
                    try:
                        sent = destination.send(view)
                        view = view[sent:]
                    except BlockingIOError:
                        time.sleep(0.001)
                if counted:
                    forwarded += len(data)
                    if delay_ms > 0:
                        time.sleep(delay_ms / 1000.0)
                    if drop_after > 0 and forwarded >= drop_after:
                        return


threads = []
with socket.socket() as listener:
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", listen_port))
    listener.listen(connection_count)
    print("READY", flush=True)
    for _ in range(connection_count):
        client, _ = listener.accept()
        thread = threading.Thread(target=relay, args=(client,))
        thread.start()
        threads.append(thread)
for thread in threads:
    thread.join()
