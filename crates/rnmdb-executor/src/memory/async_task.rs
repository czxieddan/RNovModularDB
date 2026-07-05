use std::{
    future::Future,
    panic::{self, AssertUnwindSafe},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    thread,
};

use rnmdb_common::{ErrorKind, Result, RnovError};

use super::{ExecutionResult, MemoryExecutor};

struct BlockingResultState<T> {
    result: Option<Result<T>>,
    waker: Option<Waker>,
}

pub(super) struct BlockingResultTask<T> {
    state: Arc<Mutex<BlockingResultState<T>>>,
    job: Option<Box<dyn FnOnce() -> Result<T> + Send + 'static>>,
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
        let state = Arc::clone(&task.state);
        let job = {
            let mut state = match state.lock() {
                Ok(state) => state,
                Err(_) => {
                    return Poll::Ready(Err(RnovError::new(
                        ErrorKind::Internal,
                        "async memory executor state lock poisoned",
                    )));
                }
            };
            if let Some(result) = state.result.take() {
                return Poll::Ready(result);
            }
            state.waker = Some(cx.waker().clone());
            task.job.take()
        };

        if let Some(job) = job {
            let state = Arc::clone(&task.state);
            thread::spawn(move || {
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

        Poll::Pending
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
                *task.executor = executor;
                Poll::Ready(result)
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
}
