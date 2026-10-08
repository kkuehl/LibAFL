use alloc::{borrow::Cow, rc::Rc};
use core::{cell::RefCell, fmt};

use libafl::{
    executors::ExitKind,
    inputs::{BytesInputConverter, Input, ToTargetBytesConverter},
    observers::Observer,
};
use libafl_bolts::{Error, Named};
use serde::{
    Serialize,
    de::{self, Deserialize, Deserializer, MapAccess, Visitor},
};

use crate::helper::{FridaInstrumentationHelper, FridaRuntimeTuple};
use crate::asan::asan_rt::AsanRuntime;

#[allow(clippy::unsafe_derive_deserialize)]
#[derive(Serialize, Debug)]
/// An observer that shuts down the Frida helper upon crash
/// This is necessary as we don't want to keep the instrumentation around when processing the crash
pub struct FridaHelperObserver<'a, RT, Z = BytesInputConverter> {
    #[serde(skip)]
    helper: Rc<RefCell<FridaInstrumentationHelper<'a, RT>>>,
    #[serde(skip)]
    converter: Z,
}

impl<'a, RT> FridaHelperObserver<'a, RT, BytesInputConverter>
where
    RT: FridaRuntimeTuple + 'a,
{
    /// Creates a new `FridaHelperObserver` with a default byte converter
    #[must_use]
    pub fn new(helper: Rc<RefCell<FridaInstrumentationHelper<'a, RT>>>) -> Self {
        Self {
            helper,
            converter: BytesInputConverter::new(),
        }
    }
}

impl<'a, RT, Z> FridaHelperObserver<'a, RT, Z>
where
    RT: FridaRuntimeTuple + 'a,
{
    /// Creates a new `FridaHelperObserver` with a custom converter
    #[must_use]
    pub fn with_converter(
        helper: Rc<RefCell<FridaInstrumentationHelper<'a, RT>>>,
        converter: Z,
    ) -> Self {
        Self { helper, converter }
    }
}

impl<'a, I, S, RT, Z> Observer<I, S> for FridaHelperObserver<'a, RT, Z>
where
    // S: UsesInput,
    // S::Input: HasTargetBytes,
    I: Input,
    RT: FridaRuntimeTuple + 'a,
    Z: ToTargetBytesConverter<I, S>,
{
    fn post_exec(&mut self, state: &mut S, input: &I, exit_kind: &ExitKind) -> Result<(), Error> {
        if *exit_kind == ExitKind::Crash {
            // Tearing the Stalker/Frida helper down after a crash re-enters the
            // crash handler (a "double crash"): on Windows the hard fault throws a
            // C++ exception, and on Linux the shadow-detected error already
            // panicked/aborted, so the teardown faults again — which clears the
            // handler data and drops the very crash we're trying to save.
            // Skip the full teardown and only disable the ASan allocator hooks so
            // the crash handler's own allocations don't re-enter them.
            AsanRuntime::disable_asan_hooks_global();
            return Ok(());
        }
        Ok(())
    }
}

impl<RT, Z> Named for FridaHelperObserver<'_, RT, Z> {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("FridaHelperObserver");
        &NAME
    }
}

impl<'de, RT, Z> Deserialize<'de> for FridaHelperObserver<'_, RT, Z> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FridaHelperObserverVisitor<'a, RT, Z> {
            phantom: core::marker::PhantomData<(&'a RT, Z)>,
        }

        impl<'de, 'a, RT, Z> Visitor<'de> for FridaHelperObserverVisitor<'a, RT, Z> {
            type Value = FridaHelperObserver<'a, RT, Z>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a FridaHelperObserver struct")
            }

            fn visit_map<M>(self, _map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                // Construct the struct without deserializing `helper`
                Err(de::Error::custom(
                    "Cannot deserialize `FridaHelperObserver` with a mutable reference",
                ))
            }
        }

        deserializer.deserialize_struct(
            "FridaHelperObserver",
            &[], // No fields to deserialize
            FridaHelperObserverVisitor {
                phantom: core::marker::PhantomData,
            },
        )
    }
}
