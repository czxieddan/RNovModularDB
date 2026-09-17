// crates/rnmdb-executor/src/memory/async_task.rs - RNovModularDB source module.
// Copyright (C) 2026 czxieddan
// This file is part of RNovModularDB and is provided under version 1.1 of the
// Aperip Heimdall Commons License (AHCL). The applicable version is also
// subject to the AHCL provisions concerning Continuous AHCL Licensing Segments
// and migration to later official versions. After a reasonable opportunity to
// read AHCL, all applicable Additional Restrictions, and all version notices,
// use, copying, modification, building, dependency use, deployment,
// distribution, or network operation constitutes acceptance to the extent
// permitted by applicable law.
// License notice updated: September 17, 2026.
// Official AHCL text and public notices: https://ahcl.aperip.com
// AHCL Materials Directory: .ahcl/
// Repository official or recognized AHCL copy: .ahcl/AHCL-1.1.md
// Canonical repository: https://github.com/czxieddan/RNovModularDB
// Project notice: .ahcl/AHCL-PROJECT-NOTICE.md
// Version records: .ahcl/AHCL-VERSION-ADOPTION.md
// Source and history: .ahcl/AHCL-SOURCE.md
// Dependencies and licenses: .ahcl/AHCL-DEPENDENCIES.md
// Additional Restrictions: None.
// SPDX-License-Identifier: LicenseRef-AHCL-1.1
use std::{
    future::Future,
    panic::{self, AssertUnwindSafe},
    pin::Pin,
    sync::{Arc, Mutex, OnceLock},
    task::{Context, Poll, Waker},
    thread,
};

use rnmdb_common::{ErrorKind, Result, RnovError};

use super::{ExecutionResult, MemoryExecutor};

const MAX_BLOCKING_MEMORY_TASKS: usize = 32;

struct BlockingWorkerState {
    active: usize,
    waiters: Vec<Waker>,
}

struct BlockingWorkerPermit;

static BLOCKING_WORKERS: OnceLock<Mutex<BlockingWorkerState>> = OnceLock::new();

struct BlockingResultState<T> {
    result: Option<Result<T>>,
    waker: Option<Waker>,
}

type BlockingJob<T> = Box<dyn FnOnce() -> Result<T> + Send + 'static>;

enum BlockingPoll<T> {
    Ready(Result<T>),
    Pending(Option<BlockingJob<T>>),
}

pub(super) struct BlockingResultTask<T> {
    state: Arc<Mutex<BlockingResultState<T>>>,
    job: Option<BlockingJob<T>>,
}

impl<T> BlockingResultTask<T> {
    pub(super) fn new(job: impl FnOnce() -> Result<T> + Send + 'static) -> Self {
        Self {
            state: Arc::new(Mutex::new(BlockingResultState {
                result: None,
                waker: None,
            })),
            job: Some(Box::new(job)),
        }
    }
}

impl<T> Unpin for BlockingResultTask<T> {}

impl<T: Send + 'static> Future for BlockingResultTask<T> {
    type Output = Result<T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let task = self.get_mut();
        let job = match task.take_ready_result_or_job(cx) {
            BlockingPoll::Ready(result) => return Poll::Ready(result),
            BlockingPoll::Pending(job) => job,
        };
        let Some(job) = job else {
            return Poll::Pending;
        };
        if let Err(err) = task.start_job_or_requeue(job, cx.waker()) {
            return Poll::Ready(Err(err));
        }
        Poll::Pending
    }
}

impl<T: Send + 'static> BlockingResultTask<T> {
    fn take_ready_result_or_job(&mut self, cx: &mut Context<'_>) -> BlockingPoll<T> {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => {
                return BlockingPoll::Ready(Err(RnovError::new(
                    ErrorKind::Internal,
                    "async memory executor state lock poisoned",
                )));
            }
        };
        if let Some(result) = state.result.take() {
            return BlockingPoll::Ready(result);
        }
        state.waker = Some(cx.waker().clone());
        BlockingPoll::Pending(self.job.take())
    }

    fn start_job_or_requeue(&mut self, job: BlockingJob<T>, waker: &Waker) -> Result<()> {
        let permit = match try_acquire_blocking_worker(waker)? {
            Some(permit) => permit,
            None => {
                self.job = Some(job);
                return Ok(());
            }
        };
        spawn_blocking_job(Arc::clone(&self.state), job, permit);
        Ok(())
    }
}

fn spawn_blocking_job<T: Send + 'static>(
    state: Arc<Mutex<BlockingResultState<T>>>,
    job: BlockingJob<T>,
    permit: BlockingWorkerPermit,
) {
    thread::spawn(move || {
        let _permit = permit;
        let result = panic::catch_unwind(AssertUnwindSafe(job)).unwrap_or_else(|_| {
            Err(RnovError::new(
                ErrorKind::Internal,
                "async memory executor worker panicked",
            ))
        });
        let waker = match state.lock() {
            Ok(mut state) => {
                state.result = Some(result);
                state.waker.take()
            }
            Err(_) => None,
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    });
}

fn blocking_workers() -> &'static Mutex<BlockingWorkerState> {
    BLOCKING_WORKERS.get_or_init(|| {
        Mutex::new(BlockingWorkerState {
            active: 0,
            waiters: Vec::new(),
        })
    })
}

fn try_acquire_blocking_worker(waker: &Waker) -> Result<Option<BlockingWorkerPermit>> {
    let mut state = blocking_workers().lock().map_err(|_| {
        RnovError::new(
            ErrorKind::Internal,
            "async memory executor worker limit lock poisoned",
        )
    })?;
    if state.active < MAX_BLOCKING_MEMORY_TASKS {
        state.active += 1;
        return Ok(Some(BlockingWorkerPermit));
    }
    if !state.waiters.iter().any(|waiter| waiter.will_wake(waker)) {
        state.waiters.push(waker.clone());
    }
    Ok(None)
}

impl Drop for BlockingWorkerPermit {
    fn drop(&mut self) {
        let Ok(mut state) = blocking_workers().lock() else {
            return;
        };
        state.active = state.active.saturating_sub(1);
        let waiters = std::mem::take(&mut state.waiters);
        drop(state);
        for waker in waiters {
            waker.wake();
        }
    }
}

pub(super) struct BlockingMutationTask<'a> {
    pub(super) executor: &'a mut MemoryExecutor,
    pub(super) inner: BlockingResultTask<(MemoryExecutor, Result<ExecutionResult>)>,
}

impl Unpin for BlockingMutationTask<'_> {}

impl Future for BlockingMutationTask<'_> {
    type Output = Result<ExecutionResult>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let task = self.get_mut();
        match Pin::new(&mut task.inner).poll(cx) {
            Poll::Ready(Ok((executor, result))) => {
                if result.is_ok() {
                    *task.executor = executor;
                }
                Poll::Ready(result)
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
}
