//! The service the phone's weaver asks the secure element through. Android
//! keeps it in its framework, which a recovery runs none of, so the few
//! calls the weaver makes are served here, over the secure element HAL the
//! phone's own partitions carry: the framework's own service is a reader
//! over that HAL, and so is this one.

use anyhow::{bail, Context, Result};
use std::ffi::{c_char, c_void, CStr, CString};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

/// The name the phone's weaver looks the service up by.
pub const SERVICE: &str = "android.se.omapi.ISecureElementService/default";

/// The secure element the weaver's slots are in.
const ELEMENT: &str = "android.hardware.secure_element.ISecureElement/eSE1";

/// The reader this service offers, named as Android names the phone's own
/// embedded secure element.
const READER: &str = "eSE1";

type Status = i32;
type Code = u32;

const OK: Status = 0;
const UNKNOWN_TRANSACTION: Status = -2;

#[repr(C)]
struct Class {
    _private: [u8; 0],
}

#[repr(C)]
struct Binder {
    _private: [u8; 0],
}

#[repr(C)]
struct Parcel {
    _private: [u8; 0],
}

type OnCreate = extern "C" fn(*mut c_void) -> *mut c_void;
type OnDestroy = extern "C" fn(*mut c_void);
type OnTransact = extern "C" fn(*mut Binder, Code, *const Parcel, *mut Parcel) -> Status;
type StringAllocator = extern "C" fn(*mut c_void, i32, *mut *mut c_char) -> bool;
type ArrayAllocator = extern "C" fn(*mut c_void, i32, *mut *mut i8) -> bool;

/// The calls of the phone's own binder library, which is the one its own
/// services were built against. It is opened by path: the recovery's own
/// smaller copy of that library cannot take a call, only make one.
struct Api {
    class_define: unsafe extern "C" fn(*const c_char, OnCreate, OnDestroy, OnTransact) -> *mut Class,
    new_binder: unsafe extern "C" fn(*const Class, *mut c_void) -> *mut Binder,
    dec: unsafe extern "C" fn(*mut Binder),
    user_data: unsafe extern "C" fn(*mut Binder) -> *mut c_void,
    associate: unsafe extern "C" fn(*mut Binder, *const Class) -> bool,
    add_service: unsafe extern "C" fn(*mut Binder, *const c_char) -> Status,
    get_service: unsafe extern "C" fn(*const c_char) -> *mut Binder,
    prepare: unsafe extern "C" fn(*mut Binder, *mut *mut Parcel) -> Status,
    transact: unsafe extern "C" fn(*mut Binder, Code, *mut *mut Parcel, *mut *mut Parcel, u32) -> Status,
    set_threads: unsafe extern "C" fn(u32) -> bool,
    join: unsafe extern "C" fn(),
    delete: unsafe extern "C" fn(*mut Parcel),
    write_i32: unsafe extern "C" fn(*mut Parcel, i32) -> Status,
    read_i32: unsafe extern "C" fn(*const Parcel, *mut i32) -> Status,
    write_bool: unsafe extern "C" fn(*mut Parcel, bool) -> Status,
    read_bool: unsafe extern "C" fn(*const Parcel, *mut bool) -> Status,
    write_byte: unsafe extern "C" fn(*mut Parcel, i8) -> Status,
    read_byte: unsafe extern "C" fn(*const Parcel, *mut i8) -> Status,
    write_string: unsafe extern "C" fn(*mut Parcel, *const c_char, i32) -> Status,
    read_string: unsafe extern "C" fn(*const Parcel, *mut c_void, StringAllocator) -> Status,
    write_array: unsafe extern "C" fn(*mut Parcel, *const i8, i32) -> Status,
    read_array: unsafe extern "C" fn(*const Parcel, *mut c_void, ArrayAllocator) -> Status,
    write_binder: unsafe extern "C" fn(*mut Parcel, *mut Binder) -> Status,
}

/// The classes the phone's binder library knows this process's objects by.
struct Classes {
    service: *mut Class,
    reader: *mut Class,
    session: *mut Class,
    channel: *mut Class,
    element: *mut Class,
    callback: *mut Class,
}

unsafe impl Send for Classes {}
unsafe impl Sync for Classes {}

static API: OnceLock<Api> = OnceLock::new();
static CLASSES: OnceLock<Classes> = OnceLock::new();
static HAL: OnceLock<std::result::Result<Hal, String>> = OnceLock::new();

pub fn serve() -> Result<()> {
    let loaded = Api::load().context("open the phone's own binder library")?;
    let defined = Classes::define(&loaded)?;
    let _ = API.set(loaded);
    let _ = CLASSES.set(defined);
    let api = api();
    let service = unsafe { (api.new_binder)(classes().service, null_mut()) };
    if service.is_null() {
        bail!("make the OMAPI service");
    }
    let name = CString::new(SERVICE)?;
    let status = unsafe { (api.add_service)(service, name.as_ptr()) };
    if status != OK {
        bail!("register {SERVICE}: the service directory answered {status}");
    }
    skyward_sys::kmsg(&format!("omapi: {SERVICE} is registered"))?;
    let _ = unsafe { (api.set_threads)(1) };
    unsafe { (api.join)() };
    Ok(())
}

fn api() -> &'static Api {
    API.get().expect("the binder library is opened before any call arrives")
}

fn classes() -> &'static Classes {
    CLASSES.get().expect("the classes are defined before any call arrives")
}

impl Api {
    fn load() -> Result<Api> {
        let library = open()?;
        unsafe {
            Ok(Api {
                class_define: symbol(library, "AIBinder_Class_define")?,
                new_binder: symbol(library, "AIBinder_new")?,
                dec: symbol(library, "AIBinder_decStrong")?,
                user_data: symbol(library, "AIBinder_getUserData")?,
                associate: symbol(library, "AIBinder_associateClass")?,
                add_service: symbol(library, "AServiceManager_addService")?,
                get_service: symbol(library, "AServiceManager_getService")?,
                prepare: symbol(library, "AIBinder_prepareTransaction")?,
                transact: symbol(library, "AIBinder_transact")?,
                set_threads: symbol(library, "ABinderProcess_setThreadPoolMaxThreadCount")?,
                join: symbol(library, "ABinderProcess_joinThreadPool")?,
                delete: symbol(library, "AParcel_delete")?,
                write_i32: symbol(library, "AParcel_writeInt32")?,
                read_i32: symbol(library, "AParcel_readInt32")?,
                write_bool: symbol(library, "AParcel_writeBool")?,
                read_bool: symbol(library, "AParcel_readBool")?,
                write_byte: symbol(library, "AParcel_writeByte")?,
                read_byte: symbol(library, "AParcel_readByte")?,
                write_string: symbol(library, "AParcel_writeString")?,
                read_string: symbol(library, "AParcel_readString")?,
                write_array: symbol(library, "AParcel_writeByteArray")?,
                read_array: symbol(library, "AParcel_readByteArray")?,
                write_binder: symbol(library, "AParcel_writeStrongBinder")?,
            })
        }
    }
}

fn open() -> Result<*mut c_void> {
    // The program's own libraries are searched first, which is where the
    // installed system's copy is, then the places it is kept by path: a
    // recovery's own copy of it cannot take a call.
    const NAMES: [&str; 4] = [
        "libbinder_ndk.so",
        "/mnt/system/system/lib64/libbinder_ndk.so",
        "/vendor/lib64/libbinder_ndk.so",
        "/system/lib64/libbinder_ndk.so",
    ];
    for name in NAMES {
        if name.starts_with('/') && !std::path::Path::new(name).is_file() {
            continue;
        }
        let asked = CString::new(name)?;
        let handle = unsafe { libc::dlopen(asked.as_ptr(), libc::RTLD_NOW | libc::RTLD_GLOBAL) };
        if !handle.is_null() {
            return Ok(handle);
        }
    }
    bail!("the installed system carries no binder library that opens: {}", last_error());
}

fn last_error() -> String {
    let why = unsafe { libc::dlerror() };
    if why.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(why) }.to_string_lossy().into_owned()
}

unsafe fn symbol<T: Copy>(library: *mut c_void, name: &str) -> Result<T> {
    let asked = CString::new(name)?;
    let found = libc::dlsym(library, asked.as_ptr());
    if found.is_null() {
        bail!("the phone's binder library holds no {name}");
    }
    Ok(std::mem::transmute_copy(&found))
}

impl Classes {
    fn define(api: &Api) -> Result<Classes> {
        let define = |descriptor: &str, create: OnCreate, destroy: OnDestroy, transact: OnTransact| -> Result<*mut Class> {
            let name = CString::new(descriptor)?;
            let class = unsafe { (api.class_define)(name.as_ptr(), create, destroy, transact) };
            if class.is_null() {
                bail!("define {descriptor}");
            }
            Ok(class)
        };
        Ok(Classes {
            service: define("android.se.omapi.ISecureElementService", no_create, no_destroy, service_transact)?,
            reader: define("android.se.omapi.ISecureElementReader", no_create, no_destroy, reader_transact)?,
            session: define("android.se.omapi.ISecureElementSession", keep, free_session, session_transact)?,
            channel: define("android.se.omapi.ISecureElementChannel", keep, free_channel, channel_transact)?,
            element: define("android.hardware.secure_element.ISecureElement", no_create, no_destroy, element_transact)?,
            callback: define("android.hardware.secure_element.ISecureElementCallback", no_create, no_destroy, callback_transact)?,
        })
    }
}

/// The state of an open session: the channels it has opened, and whether it
/// has been closed.
struct Session {
    closed: AtomicBool,
    channels: Mutex<Vec<u8>>,
}

/// The state of a channel the weaver transmits on.
struct Channel {
    number: u8,
    basic: bool,
    select: Option<Vec<u8>>,
    closed: AtomicBool,
}

/// The phone's secure element, as the phone's own HAL serves it.
struct Hal {
    element: *mut Binder,
    /// The callback the HAL reports the card's coming and going through,
    /// kept for as long as the HAL is used.
    #[allow(dead_code)]
    _callback: *mut Binder,
}

unsafe impl Send for Hal {}
unsafe impl Sync for Hal {}

fn element() -> Result<&'static Hal> {
    match HAL.get_or_init(|| start_element().map_err(|e| format!("{e:#}"))) {
        Ok(hal) => Ok(hal),
        Err(why) => bail!("{why}"),
    }
}

fn start_element() -> Result<Hal> {
    let api = api();
    let name = CString::new(ELEMENT)?;
    let element = unsafe { (api.get_service)(name.as_ptr()) };
    if element.is_null() {
        bail!("{ELEMENT} is not running");
    }
    if !unsafe { (api.associate)(element, classes().element) } {
        bail!("the secure element will not take the interface it is named by");
    }
    let callback = unsafe { (api.new_binder)(classes().callback, null_mut()) };
    if callback.is_null() {
        bail!("make the secure element's callback");
    }
    let hal = Hal { element, _callback: callback };
    let _ = hal.call(3, |parcel| unsafe { (api.write_binder)(parcel, callback) })?;
    Ok(hal)
}

impl Hal {
    fn call(&self, code: Code, write: impl FnOnce(*mut Parcel) -> Status) -> Result<Option<*mut Parcel>> {
        call(self.element, code, write)
    }

    fn get_atr(&self) -> Result<Option<Vec<u8>>> {
        let answer = self.call(2, |_| OK)?.context("the secure element answered nothing for its ATR")?;
        let atr = read_bytes(answer);
        unsafe { (api().delete)(answer) };
        atr
    }

    fn is_card_present(&self) -> Result<bool> {
        let answer = self.call(4, |_| OK)?.context("the secure element answered nothing about its card")?;
        let present = read_bool(answer);
        unsafe { (api().delete)(answer) };
        Ok(present)
    }

    fn open_basic(&self, aid: Option<&[u8]>, p2: i8) -> Result<Option<Vec<u8>>> {
        let answer = self
            .call(5, |parcel| {
                let status = write_bytes(parcel, aid);
                if status != OK {
                    return status;
                }
                unsafe { (api().write_byte)(parcel, p2) }
            })?
            .context("the secure element answered nothing for a basic channel")?;
        let select = read_bytes(answer);
        unsafe { (api().delete)(answer) };
        select
    }

    fn open_logical(&self, aid: Option<&[u8]>, p2: i8) -> Result<(u8, Option<Vec<u8>>)> {
        let answer = self
            .call(6, |parcel| {
                let status = write_bytes(parcel, aid);
                if status != OK {
                    return status;
                }
                unsafe { (api().write_byte)(parcel, p2) }
            })?
            .context("the secure element answered nothing for a logical channel")?;
        let opened = read_logical(answer);
        unsafe { (api().delete)(answer) };
        opened
    }

    fn transmit(&self, data: Option<&[u8]>) -> Result<Option<Vec<u8>>> {
        let answer = self.call(8, |parcel| write_bytes(parcel, data))?.context("the secure element answered nothing")?;
        let reply = read_bytes(answer);
        unsafe { (api().delete)(answer) };
        reply
    }

    fn close_channel(&self, number: u8) -> Result<()> {
        if let Some(answer) = self.call(1, |parcel| unsafe { (api().write_byte)(parcel, number as i8) })? {
            unsafe { (api().delete)(answer) };
        }
        Ok(())
    }

    fn reset(&self) -> Result<()> {
        if let Some(answer) = self.call(7, |_| OK)? {
            unsafe { (api().delete)(answer) };
        }
        Ok(())
    }
}

fn call(on: *mut Binder, code: Code, write: impl FnOnce(*mut Parcel) -> Status) -> Result<Option<*mut Parcel>> {
    let api = api();
    let mut input: *mut Parcel = null_mut();
    let status = unsafe { (api.prepare)(on, &mut input) };
    if status != OK {
        bail!("prepare a call to the secure element: {status}");
    }
    let written = write(input);
    if written != OK {
        unsafe { (api.delete)(input) };
        bail!("write a call to the secure element: {written}");
    }
    let mut output: *mut Parcel = null_mut();
    let status = unsafe { (api.transact)(on, code, &mut input, &mut output, 0) };
    if status != OK {
        bail!("the secure element answered {status}");
    }
    Ok((!output.is_null()).then_some(output))
}

extern "C" fn no_create(_args: *mut c_void) -> *mut c_void {
    null_mut()
}

extern "C" fn no_destroy(_state: *mut c_void) {}

extern "C" fn keep(state: *mut c_void) -> *mut c_void {
    state
}

extern "C" fn free_session(state: *mut c_void) {
    if !state.is_null() {
        unsafe { drop(Box::from_raw(state as *mut Session)) };
    }
}

extern "C" fn free_channel(state: *mut c_void) {
    if !state.is_null() {
        unsafe { drop(Box::from_raw(state as *mut Channel)) };
    }
}

extern "C" fn service_transact(_binder: *mut Binder, code: Code, input: *const Parcel, output: *mut Parcel) -> Status {
    let api = api();
    match code {
        1 => {
            let status = unsafe { (api.write_i32)(output, 1) };
            if status == OK {
                write_text(output, READER)
            } else {
                status
            }
        }
        2 => {
            let name = match read_text(input) {
                Ok(name) => name,
                Err(_) => return UNKNOWN_TRANSACTION,
            };
            let reader = match name.as_deref() {
                Some(name) if name == READER => unsafe { (api.new_binder)(classes().reader, null_mut()) },
                _ => null_mut(),
            };
            give(output, reader)
        }
        3 => unsafe { (api.write_i32)(output, 0) },
        _ => UNKNOWN_TRANSACTION,
    }
}

extern "C" fn reader_transact(_binder: *mut Binder, code: Code, _input: *const Parcel, output: *mut Parcel) -> Status {
    let api = api();
    match code {
        1 => {
            let present = element().and_then(|hal| hal.is_card_present()).unwrap_or(false);
            unsafe { (api.write_bool)(output, present) }
        }
        2 => {
            let session = Box::into_raw(Box::new(Session { closed: AtomicBool::new(false), channels: Mutex::new(Vec::new()) }));
            let binder = unsafe { (api.new_binder)(classes().session, session as *mut c_void) };
            if binder.is_null() {
                unsafe { drop(Box::from_raw(session)) };
            }
            give(output, binder)
        }
        3 => OK,
        4 => match element().and_then(|hal| hal.reset()) {
            Ok(()) => unsafe { (api.write_bool)(output, true) },
            Err(_) => unsafe { (api.write_bool)(output, false) },
        },
        _ => UNKNOWN_TRANSACTION,
    }
}

extern "C" fn session_transact(binder: *mut Binder, code: Code, input: *const Parcel, output: *mut Parcel) -> Status {
    let api = api();
    let state = unsafe { (api.user_data)(binder) as *mut Session };
    if state.is_null() {
        return UNKNOWN_TRANSACTION;
    }
    let session = unsafe { &*state };
    match code {
        1 => match element().and_then(|hal| hal.get_atr()) {
            Ok(atr) => write_bytes(output, atr.as_deref()),
            Err(_) => write_bytes(output, None),
        },
        2 | 3 => {
            close_channels(session);
            OK
        }
        4 => unsafe { (api.write_bool)(output, session.closed.load(Ordering::SeqCst)) },
        5 | 6 => {
            let aid = read_bytes(input).unwrap_or_default();
            let p2 = read_byte(input);
            if code == 5 {
                match element().and_then(|hal| hal.open_basic(aid.as_deref(), p2)) {
                    Ok(select) => make_channel(output, 0, true, select),
                    Err(_) => give(output, null_mut()),
                }
            } else {
                match element().and_then(|hal| hal.open_logical(aid.as_deref(), p2)) {
                    Ok((number, select)) => make_channel(output, number, false, select),
                    Err(_) => give(output, null_mut()),
                }
            }
        }
        _ => UNKNOWN_TRANSACTION,
    }
}

extern "C" fn channel_transact(binder: *mut Binder, code: Code, input: *const Parcel, output: *mut Parcel) -> Status {
    let api = api();
    let state = unsafe { (api.user_data)(binder) as *mut Channel };
    if state.is_null() {
        return UNKNOWN_TRANSACTION;
    }
    let channel = unsafe { &*state };
    match code {
        1 => {
            if !channel.closed.swap(true, Ordering::SeqCst) {
                let _ = element().and_then(|hal| hal.close_channel(channel.number));
            }
            OK
        }
        2 => unsafe { (api.write_bool)(output, channel.closed.load(Ordering::SeqCst)) },
        3 => unsafe { (api.write_bool)(output, channel.basic) },
        4 => write_bytes(output, channel.select.as_deref()),
        5 => {
            let data = read_bytes(input).unwrap_or_default();
            match element().and_then(|hal| hal.transmit(data.as_deref())) {
                Ok(reply) => write_bytes(output, reply.as_deref()),
                Err(_) => write_bytes(output, None),
            }
        }
        6 => unsafe { (api.write_bool)(output, false) },
        _ => UNKNOWN_TRANSACTION,
    }
}

extern "C" fn callback_transact(_binder: *mut Binder, _code: Code, _input: *const Parcel, _output: *mut Parcel) -> Status {
    OK
}

/// The class of the secure element itself is only used to name the
/// interface the phone's own HAL serves; no call arrives on it here.
extern "C" fn element_transact(_binder: *mut Binder, _code: Code, _input: *const Parcel, _output: *mut Parcel) -> Status {
    UNKNOWN_TRANSACTION
}

fn make_channel(output: *mut Parcel, number: u8, basic: bool, select: Option<Vec<u8>>) -> Status {
    let channel = Box::into_raw(Box::new(Channel { number, basic, select, closed: AtomicBool::new(false) }));
    let binder = unsafe { (api().new_binder)(classes().channel, channel as *mut c_void) };
    if binder.is_null() {
        unsafe { drop(Box::from_raw(channel)) };
    }
    give(output, binder)
}

fn close_channels(session: &Session) {
    let channels = session.channels.lock().expect("no panic holds a session's channels");
    if let Ok(hal) = element() {
        for number in channels.iter() {
            let _ = hal.close_channel(*number);
        }
    }
    session.closed.store(true, Ordering::SeqCst);
}

fn give(parcel: *mut Parcel, binder: *mut Binder) -> Status {
    let status = unsafe { (api().write_binder)(parcel, binder) };
    if !binder.is_null() {
        unsafe { (api().dec)(binder) };
    }
    status
}

fn write_text(parcel: *mut Parcel, text: &str) -> Status {
    let Ok(name) = CString::new(text) else {
        return UNKNOWN_TRANSACTION;
    };
    unsafe { (api().write_string)(parcel, name.as_ptr(), text.len() as i32) }
}

fn write_bytes(parcel: *mut Parcel, bytes: Option<&[u8]>) -> Status {
    match bytes {
        Some(bytes) => unsafe { (api().write_array)(parcel, bytes.as_ptr().cast(), bytes.len() as i32) },
        None => unsafe { (api().write_array)(parcel, null(), -1) },
    }
}

fn read_text(parcel: *const Parcel) -> Result<Option<String>> {
    extern "C" fn allocate(data: *mut c_void, length: i32, buffer: *mut *mut c_char) -> bool {
        let out = unsafe { &mut *(data as *mut Option<Vec<u8>>) };
        if length < 0 {
            *out = None;
            return true;
        }
        let mut bytes = vec![0u8; length as usize];
        unsafe { *buffer = bytes.as_mut_ptr().cast() };
        *out = Some(bytes);
        true
    }
    let mut bytes: Option<Vec<u8>> = None;
    let status = unsafe { (api().read_string)(parcel, &mut bytes as *mut _ as *mut c_void, allocate) };
    if status != OK {
        bail!("read text: {status}");
    }
    Ok(bytes.map(|bytes| unsafe { CStr::from_ptr(bytes.as_ptr().cast()) }.to_string_lossy().into_owned()))
}

fn read_bytes(parcel: *const Parcel) -> Result<Option<Vec<u8>>> {
    extern "C" fn allocate(data: *mut c_void, length: i32, buffer: *mut *mut i8) -> bool {
        let out = unsafe { &mut *(data as *mut Option<Vec<u8>>) };
        if length < 0 {
            *out = None;
            return true;
        }
        let mut bytes = vec![0u8; length as usize];
        unsafe { *buffer = bytes.as_mut_ptr().cast() };
        *out = Some(bytes);
        true
    }
    let mut bytes: Option<Vec<u8>> = None;
    let status = unsafe { (api().read_array)(parcel, &mut bytes as *mut _ as *mut c_void, allocate) };
    if status != OK {
        bail!("read bytes: {status}");
    }
    Ok(bytes)
}

fn read_byte(parcel: *const Parcel) -> i8 {
    let mut value: i8 = 0;
    let status = unsafe { (api().read_byte)(parcel, &mut value) };
    if status == OK {
        value
    } else {
        0
    }
}

fn read_bool(parcel: *const Parcel) -> bool {
    let mut value = false;
    let status = unsafe { (api().read_bool)(parcel, &mut value) };
    status == OK && value
}

fn read_logical(parcel: *const Parcel) -> Result<(u8, Option<Vec<u8>>)> {
    let api = api();
    let mut present: i32 = 0;
    let status = unsafe { (api.read_i32)(parcel, &mut present) };
    if status != OK {
        bail!("read whether the channel is there: {status}");
    }
    if present == 0 {
        bail!("the secure element left the channel out");
    }
    let mut size: i32 = 0;
    let status = unsafe { (api.read_i32)(parcel, &mut size) };
    if status != OK {
        bail!("read how long the channel is: {status}");
    }
    let mut number: i8 = 0;
    let status = unsafe { (api.read_byte)(parcel, &mut number) };
    if status != OK {
        bail!("read the channel's number: {status}");
    }
    Ok((number as u8, read_bytes(parcel)?))
}
