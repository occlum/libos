use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Weak;

use ringbuf::{Consumer as RbConsumer, Producer as RbProducer, RingBuffer};

use super::{IoEvents, IoNotifier};
use crate::events::{Event, EventFilter, Notifier, Observer, Waiter, WaiterQueueObserver};
use crate::prelude::*;

/// A unidirectional communication channel, intended to implement IPC, e.g., pipe,
/// unix domain sockets, etc.
pub struct Channel<I> {
    producer: Producer<I>,
    consumer: Consumer<I>,
    uid: usize, // Can be used to identify a channel
}

impl<I> Channel<I> {
    /// Create a new channel.
    pub fn new(capacity: usize) -> Result<Self> {
        let state = Arc::new(State::new());

        let rb = RingBuffer::new(capacity);
        let uid = Self::gen_uid(&rb);
        let (rb_producer, rb_consumer) = rb.split();
        let mut producer = Producer::new(rb_producer, state.clone());
        let mut consumer = Consumer::new(rb_consumer, state.clone());

        // The events on an endpoint is not triggered by itself, but its peer.
        // For example, a producer becomes writable (IoEvents::OUT) only if
        // its peer consumer gets read. So an endpoint needs to hold a
        // reference to the notifier of its peer.
        producer.peer_notifier = Arc::downgrade(&consumer.notifier);
        consumer.peer_notifier = Arc::downgrade(&producer.notifier);
        // An endpoint registers itself as an observer to its own notifier so
        // that it can be waken up by its peer.
        producer.notifier.register(
            Arc::downgrade(&producer.observer) as Weak<dyn Observer<_>>,
            None,
            None,
        );
        consumer.notifier.register(
            Arc::downgrade(&consumer.observer) as Weak<dyn Observer<_>>,
            None,
            None,
        );

        Ok(Self {
            producer,
            consumer,
            uid,
        })
    }

    // Use a random number for uid
    fn gen_uid(ring_buf: &RingBuffer<I>) -> usize {
        use crate::util::random;
        let mut random_buf: [u8; 8] = [0u8; 8]; // same length as usize
        random::get_random(&mut random_buf).expect("failed to get random number");
        u64::from_le_bytes(random_buf) as usize
    }

    /// Push an item into the channel.
    pub fn push(&self, item: I) -> Result<()> {
        self.producer.push(item)
    }

    /// Push an non-copy item into the channel.
    ///
    /// Non-copy items need special treatment because once passed as an argument
    /// to this method, an non-copy object is considered **moved** from the
    /// caller to the callee (this method) by Rust. This makes it impossible for
    /// the caller to retry calling this method with the same input item
    /// in case of an `EAGAIN` or `EINTR` error. For this reason, we need a way
    /// for the caller to get back the ownership of the input item upon error.
    /// Thus, an extra argument is added to this method.
    // TODO: implement this method in the future when pushing items individually is
    // really needed
    pub fn push_noncopy(&self, item: I, retry: &mut Option<I>) -> Result<()> {
        unimplemented!();
    }

    /// Pop an item out of the channel.
    pub fn pop(&self) -> Result<Option<I>> {
        self.consumer.pop()
    }

    /// Turn the channel into a pair of producer and consumer.
    pub fn split(self) -> (Producer<I>, Consumer<I>) {
        let Channel {
            producer,
            consumer,
            uid,
        } = self;
        (producer, consumer)
    }

    pub fn consumer(&self) -> &Consumer<I> {
        &self.consumer
    }

    pub fn producer(&self) -> &Producer<I> {
        &self.producer
    }

    pub fn uid(&self) -> usize {
        self.uid
    }

    pub fn capacity(&self) -> usize {
        self.consumer.capacity()
    }

    pub fn items_to_consume(&self) -> usize {
        self.consumer.items_to_consume()
    }

    pub fn set_nonblocking(&self, nonblocking: bool) {
        self.consumer.set_nonblocking(nonblocking);
        self.producer.set_nonblocking(nonblocking);
    }

    pub fn shutdown(&self) {
        self.consumer.shutdown();
        self.producer.shutdown();
    }
}

impl<I: Copy> Channel<I> {
    /// Push a slice of items into the channel.
    pub fn push_slice(&self, items: &[I]) -> Result<usize> {
        self.producer.push_slice(items)
    }

    /// Pop a slice of items from the channel.
    pub fn pop_slice(&self, items: &mut [I]) -> Result<usize> {
        self.consumer.pop_slice(items)
    }
}

// A macro to implemennt the common part of the two end point types, Producer<I>
// and Consumer<I>.
macro_rules! impl_end_point_type {
    ($(#[$attr:meta])* $vis:vis struct $end_point:ident<$i:ident> {
        inner: $inner:ident<$_:ident>,
    }) => (
        /// An endpoint is either the producer or consumer of a channel.
        $(#[$attr])* $vis struct $end_point<$i> {
            inner: SgxMutex<$inner<$i>>,
            state: Arc<State>,
            observer: Arc<WaiterQueueObserver<IoEvents>>,
            notifier: Arc<IoNotifier>,
            peer_notifier: Weak<IoNotifier>,
            is_nonblocking: AtomicBool,
        }

        impl<$i> $end_point<$i> {
            fn new(inner: $inner<$i>, state: Arc<State>) -> Self {
                let inner = SgxMutex::new(inner);
                let observer = WaiterQueueObserver::new();
                let notifier = Arc::new(IoNotifier::new());
                let peer_notifier = Default::default();
                let is_nonblocking = AtomicBool::new(false);
                Self {
                    inner,
                    state,
                    observer,
                    notifier,
                    peer_notifier,
                    is_nonblocking,
                }
            }

            /// Returns the I/O notifier.
            ///
            /// An interesting observer can receive I/O events of the endpoint by
            /// registering itself to this notifier.
            pub fn notifier(&self) -> &IoNotifier {
                &self.notifier
            }

            /// Returns whether the endpoint is non-blocking.
            ///
            /// By default, a channel is blocking.
            pub fn is_nonblocking(&self) -> bool {
                self.is_nonblocking.load(Ordering::Acquire)
            }

            /// Set whether the endpoint is non-blocking.
            pub fn set_nonblocking(&self, nonblocking: bool) {
                self.is_nonblocking.store(nonblocking, Ordering::Release);

                if nonblocking {
                    // Wake all threads that are blocked on pushing/popping this endpoint
                    self.observer.waiter_queue().dequeue_and_wake_all();
                }
            }

            fn trigger_peer_events(&self, events: &IoEvents) {
                if let Some(peer_notifier) = self.peer_notifier.upgrade() {
                    peer_notifier.broadcast(events);
                }
            }
        }
    )
}

// Just like a normal loop, except that a waiter queue (as well as a waiter)
// is used to avoid busy loop. This macro is used in the push/pop implementation
// below.
macro_rules! waiter_loop {
    ($loop_body: block, $waiter_queue: expr) => {
        // Try without creating a waiter. This saves some CPU cycles if the
        // first attempt succeeds.
        {
            $loop_body
        }

        // The main loop
        let waiter = Waiter::new();
        let waiter_queue = $waiter_queue;
        loop {
            waiter_queue.reset_and_enqueue(&waiter);

            {
                $loop_body
            }

            waiter.wait(None)?;
        }
    };
}

impl_end_point_type! {
    /// Producer is the writable endpoint of a channel.
    pub struct Producer<I> {
        inner: RbProducer<I>,
    }
}

impl<I> Producer<I> {
    pub fn push(&self, mut item: I) -> Result<()> {
        waiter_loop!(
            {
                let mut rb_producer = self.inner.lock().unwrap();
                if self.is_self_shutdown() || self.is_peer_shutdown() {
                    return_errno!(EPIPE, "one or both endpoints have been shutdown");
                }

                item = match rb_producer.push(item) {
                    Ok(()) => {
                        drop(rb_producer);
                        self.trigger_peer_events(&IoEvents::IN);
                        return Ok(());
                    }
                    Err(item) => item,
                };

                if self.is_nonblocking() {
                    return_errno!(EAGAIN, "try again later");
                }
            },
            self.observer.waiter_queue()
        );
    }

    pub fn poll(&self) -> IoEvents {
        let mut events = IoEvents::empty();

        let writable = {
            let mut rb_producer = self.inner.lock().unwrap();
            !rb_producer.is_full() || self.is_self_shutdown()
        };
        if writable {
            events |= IoEvents::OUT;
        }

        if self.is_peer_shutdown() {
            events |= IoEvents::ERR;
        }

        events
    }

    pub fn shutdown(&self) {
        {
            // It is important to hold this lock while updating the state
            let inner = self.inner.lock().unwrap();
            if self.state.is_producer_shutdown() {
                return;
            }
            self.state.set_producer_shutdown();
        }

        // The shutdown of the producer triggers hangup events on the consumer
        self.trigger_peer_events(&IoEvents::HUP);
        // Wake all threads that are blocked on pushing to this producer
        self.observer.waiter_queue().dequeue_and_wake_all();
    }

    pub fn is_self_shutdown(&self) -> bool {
        self.state.is_producer_shutdown()
    }

    pub fn is_peer_shutdown(&self) -> bool {
        self.state.is_consumer_shutdown()
    }
}

impl<I: Copy> Producer<I> {
    pub fn push_slice(&self, items: &[I]) -> Result<usize> {
        self.push_slices(&[items])
    }

    pub fn push_slices(&self, item_slices: &[&[I]]) -> Result<usize> {
        let len: usize = item_slices.iter().map(|slice| slice.len()).sum();
        if len == 0 {
            return Ok(0);
        }

        waiter_loop!(
            {
                let mut rb_producer = self.inner.lock().unwrap();
                if self.is_self_shutdown() || self.is_peer_shutdown() {
                    return_errno!(EPIPE, "one or both endpoints have been shutdown");
                }

                let mut total_count = 0;
                for items in item_slices {
                    let count = rb_producer.push_slice(items);
                    total_count += count;
                    if count < items.len() {
                        break;
                    } else {
                        continue;
                    }
                }

                if total_count > 0 {
                    drop(rb_producer);
                    self.trigger_peer_events(&IoEvents::IN);
                    return Ok(total_count);
                }

                if self.is_nonblocking() {
                    return_errno!(EAGAIN, "try again later");
                }
            },
            self.observer.waiter_queue()
        );
    }
}

impl<I> Drop for Producer<I> {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl_end_point_type! {
    /// Consumer is the readable endpoint of a channel.
    pub struct Consumer<I> {
        inner: RbConsumer<I>,
    }
}

impl<I> Consumer<I> {
    pub fn pop(&self) -> Result<Option<I>> {
        waiter_loop!(
            {
                let mut rb_consumer = self.inner.lock().unwrap();
                if self.is_self_shutdown() {
                    return_errno!(EPIPE, "this endpoint has been shutdown");
                }

                if let Some(item) = rb_consumer.pop() {
                    drop(rb_consumer);
                    self.trigger_peer_events(&IoEvents::OUT);
                    return Ok(Some(item));
                }

                if self.is_peer_shutdown() {
                    return Ok(None);
                }
                if self.is_nonblocking() {
                    return_errno!(EAGAIN, "try again later");
                }
            },
            self.observer.waiter_queue()
        );
    }

    pub fn poll(&self) -> IoEvents {
        let mut events = IoEvents::empty();

        let readable = {
            let mut rb_consumer = self.inner.lock().unwrap();
            !rb_consumer.is_empty() || self.is_self_shutdown()
        };
        if readable {
            events |= IoEvents::IN;
        }

        if self.is_peer_shutdown() {
            events |= IoEvents::HUP;
        }

        events
    }

    pub fn shutdown(&self) {
        {
            // It is important to hold this lock while updating the state
            let inner = self.inner.lock().unwrap();
            if self.state.is_consumer_shutdown() {
                return;
            }
            self.state.set_consumer_shutdown();
        }

        // The consumer being shutdown triggers error on the producer
        self.trigger_peer_events(&IoEvents::ERR);
        // Wake all threads that are blocked on popping from this consumer
        self.observer.waiter_queue().dequeue_and_wake_all();
    }

    pub fn is_self_shutdown(&self) -> bool {
        self.state.is_consumer_shutdown()
    }

    pub fn is_peer_shutdown(&self) -> bool {
        self.state.is_producer_shutdown()
    }

    pub fn items_to_consume(&self) -> usize {
        if self.is_self_shutdown() {
            0
        } else {
            self.inner.lock().unwrap().len()
        }
    }

    pub fn capacity(&self) -> usize {
        let rb_consumer = self.inner.lock().unwrap();
        rb_consumer.capacity()
    }

    // Get the length of data stored in the buffer
    pub fn ready_len(&self) -> usize {
        let rb_consumer = self.inner.lock().unwrap();
        rb_consumer.len()
    }
}

impl<I: Copy> Consumer<I> {
    pub fn pop_slice(&self, items: &mut [I]) -> Result<usize> {
        self.pop_slices(&mut [items])
    }

    pub fn pop_slices(&self, item_slices: &mut [&mut [I]]) -> Result<usize> {
        let len: usize = item_slices.iter().map(|slice| slice.len()).sum();
        if len == 0 {
            return Ok(0);
        }

        waiter_loop!(
            {
                let mut rb_consumer = self.inner.lock().unwrap();
                if self.is_self_shutdown() {
                    return_errno!(EPIPE, "this endpoint has been shutdown");
                }

                let mut total_count = 0;
                for items in item_slices.iter_mut() {
                    let count = rb_consumer.pop_slice(items);
                    total_count += count;
                    if count < items.len() {
                        break;
                    } else {
                        continue;
                    }
                }

                if total_count > 0 {
                    drop(rb_consumer);
                    self.trigger_peer_events(&IoEvents::OUT);
                    return Ok(total_count);
                };

                if self.is_peer_shutdown() {
                    return Ok(0);
                }
                if self.is_nonblocking() {
                    return_errno!(EAGAIN, "try again later");
                }
            },
            self.observer.waiter_queue()
        );
    }
}

impl<I> Drop for Consumer<I> {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// The state of a channel shared by the two endpoints of a channel.
struct State {
    is_producer_shutdown: AtomicBool,
    is_consumer_shutdown: AtomicBool,
}

impl State {
    pub fn new() -> Self {
        Self {
            is_producer_shutdown: AtomicBool::new(false),
            is_consumer_shutdown: AtomicBool::new(false),
        }
    }

    pub fn is_producer_shutdown(&self) -> bool {
        self.is_producer_shutdown.load(Ordering::Acquire)
    }

    pub fn is_consumer_shutdown(&self) -> bool {
        self.is_consumer_shutdown.load(Ordering::Acquire)
    }

    pub fn set_producer_shutdown(&self) {
        self.is_producer_shutdown.store(true, Ordering::Release)
    }

    pub fn set_consumer_shutdown(&self) {
        self.is_consumer_shutdown.store(true, Ordering::Release)
    }
}
