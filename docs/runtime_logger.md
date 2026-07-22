# Runtime logger contract

## Purpose and ownership

`libpsycho/src/logger/impl.rs` owns the process-wide asynchronous logger used by
the early core DLL and the xNVSE plugins. Producers format a complete record and
enqueue it without performing console or file I/O. A single consumer owns both
outputs.

## Startup and shutdown

Immediate initialization opens the configured file and starts the consumer.
Deferred initialization only registers the logger and queues records; the
consumer and file are created later, outside the Windows loader lock, by
`Logger::start_deferred`. The receiver is single-owner and can be claimed only
once.

The queue contains ordered message, flush, and shutdown commands. A flush is a
barrier: its acknowledgement is sent only after all earlier records reached the
outputs. Shutdown flushes and exits after all earlier commands. Calls made before
the deferred consumer starts stay queued and retain their order.

## Performance and failure behavior

The consumer blocks in the channel receiver while idle. It does not poll, yield,
or wake on a timer. Sending a record wakes it. The channel is unbounded so normal
logging never waits for capacity; records can still be lost after the receiver
has permanently closed, matching the logger's post-shutdown contract.

File output is flushed after every record for crash survivability. Diagnostic
producers must therefore aggregate high-frequency telemetry rather than relying
on logger-side buffering. Console and file write errors remain non-fatal.

## Validation

Unit tests cover deferred ordering, concurrent producers, idle wakeup, ordered
flush, and shutdown draining. Runtime acceptance is an idle logger thread with no
periodic wakeups while new records and shutdown still wake it promptly.
