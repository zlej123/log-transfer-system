// Bounded-pool ownership, backpressure and shutdown test.
#include "../server/net.hpp"
#include "../server/thread_pool.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <memory>
#include <thread>
#include <vector>

struct TestConnection {
    explicit TestConnection(lgx::Socket value) : socket(std::move(value)) {}
    lgx::Socket socket;
};

struct TestTask {
    using ConnectionType = TestConnection;
    std::shared_ptr<TestConnection> connection;
    std::chrono::steady_clock::time_point accepted_at;
};

int main()
{
    std::atomic<int> active{0};
    std::atomic<int> maximum{0};
    lgx::BoundedThreadPool<TestTask> pool(
        2, 2, std::chrono::seconds(10),
        [&](TestTask task) {
            const int now = active.fetch_add(1) + 1;
            int seen = maximum.load();
            while (now > seen && !maximum.compare_exchange_weak(seen, now)) {}
            char byte = 0;
            ::recv(task.connection->socket.get(), &byte, 1, 0);
            active.fetch_sub(1);
        });

    std::vector<lgx::Socket> peers;
    bool fifth_accepted = true;
    for (int i = 0; i < 5; ++i) {
        int pair[2]{};
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) return 2;
        auto connection = std::make_shared<TestConnection>(lgx::Socket(pair[0]));
        peers.emplace_back(pair[1]);
        TestTask task{connection, std::chrono::steady_clock::now()};
        const bool accepted = pool.try_submit(std::move(task));
        if (i == 4) fifth_accepted = accepted;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    const auto started = std::chrono::steady_clock::now();
    pool.stop();
    const auto elapsed = std::chrono::steady_clock::now() - started;

    if (fifth_accepted || maximum.load() > 2 ||
        elapsed > std::chrono::seconds(2)) {
        std::printf("FAIL accepted5=%d max=%d stop_ms=%lld\n",
                    fifth_accepted ? 1 : 0, maximum.load(),
                    (long long)std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count());
        return 1;
    }
    std::printf("THREAD POOL TEST PASSED\n");
    return 0;
}
