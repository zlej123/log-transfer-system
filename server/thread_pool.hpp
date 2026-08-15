// Fixed-size connection pool with a bounded admission queue.
#pragma once

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <utility>
#include <vector>

#include <sys/socket.h>

namespace lgx {

template <typename Task>
class BoundedThreadPool {
public:
    using Handler = std::function<void(Task)>;
    using Connection = typename Task::ConnectionType;

    BoundedThreadPool(std::size_t worker_count, std::size_t queue_capacity,
                      std::chrono::seconds max_queue_age, Handler handler)
        : capacity_(queue_capacity), max_queue_age_(max_queue_age),
          handler_(std::move(handler)), active_connections_(worker_count)
    {
        workers_.reserve(worker_count);
        try {
            for (std::size_t i = 0; i < worker_count; ++i)
                workers_.emplace_back([this, i] { worker_loop(i); });
        } catch (...) {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                stopping_ = true;
            }
            ready_.notify_all();
            for (auto& worker : workers_)
                if (worker.joinable()) worker.join();
            throw;
        }
    }

    ~BoundedThreadPool() { stop(); }

    bool try_submit(Task task)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (stopping_ || queue_.size() >= capacity_) return false;
        queue_.push_back(std::move(task));
        ready_.notify_one();
        return true;
    }

    void stop()
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (stopping_) return;
            stopping_ = true;
            queue_.clear(); // task RAII owners close queued sockets here
            for (const auto& connection : active_connections_)
                if (connection) connection->socket.shutdown_both();
        }
        ready_.notify_all();
        for (auto& worker : workers_)
            if (worker.joinable()) worker.join();
    }

    std::size_t queued() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }

private:
    BoundedThreadPool(const BoundedThreadPool&);
    BoundedThreadPool& operator=(const BoundedThreadPool&);

    void worker_loop(std::size_t index)
    {
        for (;;) {
            std::optional<Task> task;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                ready_.wait(lock, [this] { return stopping_ || !queue_.empty(); });
                if (stopping_) return;
                task.emplace(std::move(queue_.front()));
                queue_.pop_front();
                const auto age = std::chrono::steady_clock::now() - task->accepted_at;
                if (age > max_queue_age_) {
                    task.reset();
                    continue;
                }
                active_connections_[index] = task->connection;
            }
            try {
                handler_(std::move(*task));
            } catch (...) {
                // The per-connection handler logs details; the worker survives.
            }
            {
                std::lock_guard<std::mutex> lock(mutex_);
                active_connections_[index].reset();
            }
        }
    }

    const std::size_t capacity_;
    const std::chrono::seconds max_queue_age_;
    Handler handler_;
    mutable std::mutex mutex_;
    std::condition_variable ready_;
    std::deque<Task> queue_;
    std::vector<std::thread> workers_;
    std::vector<std::shared_ptr<Connection>> active_connections_;
    bool stopping_ = false;
};

} // namespace lgx
