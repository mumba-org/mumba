// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::{
    cmp::min,
    collections::HashMap,
    os::windows::io::RawHandle,
    sync::{Arc, Mutex},
    time::Duration,
};

use winapi::{
    shared::{
        minwindef::{DWORD, FALSE},
        winerror::{ERROR_INVALID_PARAMETER, WAIT_TIMEOUT},
    },
    um::{synchapi::WaitForMultipleObjects, winbase::WAIT_OBJECT_0},
};

use super::super::{
    errno_result, Error, Event, EventTrigger, EventType, PollToken, Result, TriggeredEvent,
};
use crate::descriptor::{AsRawDescriptor, Descriptor};
use crate::error;
// MAXIMUM_WAIT_OBJECTS = 64
pub const MAXIMUM_WAIT_OBJECTS: usize = winapi::um::winnt::MAXIMUM_WAIT_OBJECTS as usize;

// TODO(145170451) rizhang: implement round robin if event size is greater than 64

struct RegisteredHandles<T: PollToken> {
    triggers: HashMap<Descriptor, T>,
    raw_handles: Vec<Descriptor>,
}

pub struct EventContext<T: PollToken> {
    registered_handles: Arc<Mutex<RegisteredHandles<T>>>,

    // An internally-used event to signify that the list of handles has been modified
    // mid-wait. This is to solve for instances where Thread A has started waiting and
    // Thread B adds an event trigger, which needs to notify Thread A a change has been
    // made.
    handles_modified_event: Event,
}

impl<T: PollToken> EventContext<T> {
    pub fn new() -> Result<EventContext<T>> {
        let new = EventContext {
            registered_handles: Arc::new(Mutex::new(RegisteredHandles {
                triggers: HashMap::new(),
                raw_handles: Vec::new(),
            })),
            handles_modified_event: Event::new().unwrap(),
        };
        // The handles-modified event will be everpresent on the raw_handles to be waited
        // upon to ensure the wait stops and we update it any time the handles list is
        // modified.
        new.registered_handles
            .lock()
            .unwrap()
            .raw_handles
            .push(Descriptor(new.handles_modified_event.as_raw_descriptor()));
        Ok(new)
    }

    /// Creates a new EventContext with the the associated triggers.
    pub fn build_with(triggers: &[EventTrigger<T>]) -> Result<EventContext<T>> {
        let ctx = EventContext::new()?;
        ctx.add_many(triggers)?;
        Ok(ctx)
    }

    /// Adds a trigger to the EventContext.
    pub fn add(&self, trigger: EventTrigger<T>) -> Result<()> {
        self.add_for_event(trigger, EventType::Read)
    }

    /// Adds a trigger to the EventContext.
    pub fn add_many(&self, triggers: &[EventTrigger<T>]) -> Result<()> {
        for trigger in triggers {
            self.add(trigger.clone())?
        }
        Ok(())
    }

    pub fn add_for_event(&self, trigger: EventTrigger<T>, _event_type: EventType) -> Result<()> {
        let mut registered_handles_locked = self.registered_handles.lock().unwrap();
        if registered_handles_locked
            .triggers
            .contains_key(&Descriptor(trigger.event))
        {
            // If this handle is already added, silently succeed with a noop
            return Ok(());
        }
        registered_handles_locked
            .triggers
            .insert(Descriptor(trigger.event), trigger.token);
        registered_handles_locked
            .raw_handles
            .push(Descriptor(trigger.event));
        // Windows doesn't support watching for specific types of events. Just treat this
        // like a normal add and do nothing with event_type
        self.handles_modified_event.write(1)
    }

    pub fn modify(&self, trigger: EventTrigger<T>, _event_type: EventType) -> Result<()> {
        let mut registered_handles_locked = self.registered_handles.lock().unwrap();
        if let std::collections::hash_map::Entry::Occupied(mut e) = registered_handles_locked
            .triggers
            .entry(Descriptor(trigger.event))
        {
            e.insert(trigger.token);
        }
        // Windows doesn't support watching for specific types of events. Ignore the event_type
        // and just modify the token.
        self.handles_modified_event.write(1)
    }

    pub fn remove(&self, event_handle: &dyn AsRawDescriptor) -> Result<()> {
        let mut registered_handles_locked = self.registered_handles.lock().unwrap();
        let result = registered_handles_locked
            .triggers
            .remove(&Descriptor(event_handle.as_raw_descriptor()));
        if result.is_none() {
            // this handle was not registered in the first place. Silently succeed with a noop
            return Ok(());
        }
        let index = registered_handles_locked
            .raw_handles
            .iter()
            .position(|item| item == &Descriptor(event_handle.as_raw_descriptor()))
            .unwrap();
        registered_handles_locked.raw_handles.remove(index);
        self.handles_modified_event.write(1)
    }

    pub fn clear(&self) -> Result<()> {
        let mut registered_handles_locked = self.registered_handles.lock().unwrap();
        registered_handles_locked.triggers.clear();
        registered_handles_locked.raw_handles.clear();

        registered_handles_locked
            .raw_handles
            .push(Descriptor(self.handles_modified_event.as_raw_descriptor()));
        self.handles_modified_event.write(1)
    }

    /// Waits for one or more of the registered triggers to become signaled.
    pub fn wait(&self) -> Result<Vec<TriggeredEvent<T>>> {
        self.wait_timeout(Duration::new(i64::MAX as u64, 0))
    }

    pub fn wait_timeout(&self, timeout: Duration) -> Result<Vec<TriggeredEvent<T>>> {
        let raw_handles_list: Vec<RawHandle> = self
            .registered_handles
            .lock()
            .unwrap()
            .raw_handles
            .clone()
            .into_iter()
            .map(|handle| handle.0)
            .collect();
        if raw_handles_list.len() == 1 {
            // Disallow calls with no handles to wait on. Do not include the handles_modified_event
            // which always populates the list.
            return Err(Error::new(ERROR_INVALID_PARAMETER));
        }
        let result = unsafe {
            WaitForMultipleObjects(
                raw_handles_list.len() as DWORD,
                raw_handles_list.as_ptr(),
                FALSE, // return when one event is signaled
                timeout.as_millis() as DWORD,
            )
        };
        let handles_len = min(MAXIMUM_WAIT_OBJECTS, raw_handles_list.len()) as usize;

        const MAXIMUM_WAIT_OBJECTS_U32: u32 = MAXIMUM_WAIT_OBJECTS as u32;
        match result as u32 {
            WAIT_OBJECT_0..=MAXIMUM_WAIT_OBJECTS_U32 => {
                let mut event_index = (result - WAIT_OBJECT_0) as usize;
                if event_index >= handles_len {
                    // This is not a valid index and should return an error. This case should not be possible
                    // and will likely not return a meaningful system error code, but is still an invalid case.
                    error!("Wait returned index out of range");
                    return errno_result();
                }
                if event_index == 0 {
                    // The handles list has been modified and triggered the wait, try again with the updated
                    // handles list. Note it is possible the list was modified again after the wait which will
                    // trigger the handles_modified_event again, but that will only err towards the safe side
                    // of recursing an extra time.
                    let _ = self.handles_modified_event.read();
                    return self.wait_timeout(timeout);
                }

                let mut events_to_return: Vec<TriggeredEvent<T>> = vec![];
                // Multiple events may be triggered at once, but WaitForMultipleObjects will only return one.
                // Once it returns, loop through the remaining triggers checking each to ensure they haven't
                // also been triggered.
                let mut handles_offset: usize = 0;
                loop {
                    let event_to_return = raw_handles_list[event_index + handles_offset];
                    events_to_return.push(TriggeredEvent {
                        token: T::from_raw_token(
                            self.registered_handles
                                .lock()
                                .unwrap()
                                .triggers
                                .get(&Descriptor(event_to_return))
                                .unwrap()
                                .as_raw_token(),
                        ),
                        // In Windows, events aren't associated with read/writability, so for cross-
                        // compatability, associate with both.
                        is_readable: true,
                        is_writable: true,
                        is_hungup: false,
                    });

                    handles_offset += event_index + 1;
                    if handles_offset >= handles_len {
                        break;
                    }
                    event_index = (unsafe {
                        WaitForMultipleObjects(
                            (raw_handles_list.len() - handles_offset) as DWORD,
                            raw_handles_list[handles_offset..].as_ptr(),
                            FALSE, // return when one event is signaled
                            0,     /* instantaneous timeout */
                        )
                    } - WAIT_OBJECT_0) as usize;

                    if event_index >= (handles_len - handles_offset) {
                        // This indicates a failure condition, as return values greater than the length
                        // of the provided array are reserved for failures.
                        break;
                    }
                }

                Ok(events_to_return)
            }
            WAIT_TIMEOUT => Ok(vec![]),
            // Invalid cases. This is most likely an WAIT_FAILED, but anything not matched by the
            // above is an error case.
            _ => errno_result(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic]
    fn error_on_empty_context_wait() {
        let ctx: EventContext<u32> = EventContext::new().unwrap();
        let dur = Duration::from_millis(10);
        ctx.wait_timeout(dur).unwrap();
    }
}
