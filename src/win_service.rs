use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::sync::{Arc, mpsc, Mutex};
use std::thread;
use std::time::Duration;
use lazy_static::lazy_static;
use log::{error, info};

use windows_service::{define_windows_service, service::{
    ServiceControl, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
}, service_control_handler::ServiceControlHandlerResult, service_dispatcher, Result, service_control_handler};
use windows_service::service::ServiceControlAccept;
use alfis::{Context, Settings};
use crate::start_services;

// Define the service entry point and its behavior
define_windows_service!(ffi_service_main, alfis_service_main);

pub const SERVICE_NAME: &str = "ALFIS";
pub const SERVICE_DESCRIPTION: &str = "Alternative Free Identity System, DNS on a smallest blockchain.";

lazy_static! {
    // Sending parameters through static variables. Don't do this!
    static ref SETTINGS: Mutex<(Option<Settings>, Option<Arc<Mutex<Context>>>)> = Mutex::new((None, None));
}

pub fn start_service(settings: Settings, context: Arc<Mutex<Context>>) -> Result<()> {
    if let Ok(mut option) = SETTINGS.lock() {
        let _ = option.0.insert(settings);
        let _ = option.1.insert(context);
    }
    // Register the service entry point and control handler
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

fn alfis_service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service_logic() {
        error!("Error while starting service: {}", e);
    }
}

fn run_service_logic() -> Result<()> {
    let (shutdown_tx, shutdown_rx) = mpsc::channel();
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        info!("Event: {:?}", &control_event);
        match control_event {
            ServiceControl::Stop => {
                // Handle stop event and return control back to the system.
                shutdown_tx.send(()).unwrap();
                ServiceControlHandlerResult::NoError
            }
            // All services must accept Interrogate even if it's a no-op.
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    // Register system service event handler
    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    let next_status = ServiceStatus {
        // Should match the one from system service registry
        service_type: ServiceType::OWN_PROCESS,
        // The new state
        current_state: ServiceState::Running,
        // Accept stop events when running
        controls_accepted: ServiceControlAccept::STOP,
        // Used to report an error when starting or stopping only, otherwise must be zero
        exit_code: ServiceExitCode::Win32(0),
        // Only used for pending states, otherwise must be zero
        checkpoint: 0,
        // Only used for pending states, otherwise must be zero
        wait_hint: Duration::default(),
        // Unused for setting status
        process_id: None,
    };

    // Tell the system that the service is running now
    status_handle.set_service_status(next_status)?;

    let (settings, context) = {
        let mut lock = SETTINGS.lock().unwrap();
        (lock.0.take().unwrap(), lock.1.take().unwrap())
    };
    let (_dns_server_ok, _miner, _network) = start_services(&settings, &context);

    loop {
        thread::sleep(Duration::from_secs(1));
        // Poll shutdown event.
        match shutdown_rx.recv_timeout(Duration::from_secs(1)) {
            // Break the loop either upon stop or channel disconnect
            Ok(_) | Err(mpsc::RecvTimeoutError::Disconnected) => break,

            // Continue work if no events were received within the timeout
            Err(mpsc::RecvTimeoutError::Timeout) => (),
        };
    }

    let next_status = ServiceStatus {
        // Should match the one from system service registry
        service_type: ServiceType::OWN_PROCESS,
        // The new state
        current_state: ServiceState::Stopped,
        // Accept stop events when running
        controls_accepted: ServiceControlAccept::empty(),
        // Used to report an error when starting or stopping only, otherwise must be zero
        exit_code: ServiceExitCode::Win32(0),
        // Only used for pending states, otherwise must be zero
        checkpoint: 0,
        // Only used for pending states, otherwise must be zero
        wait_hint: Duration::default(),
        // Unused for setting status
        process_id: None,
    };
    status_handle.set_service_status(next_status)?;
    Ok(())
}

// Function to install a Windows service
pub fn install_service(service_name: &str, bin_path: &str) {
    use windows_service::service_manager::*;
    use windows_service::service::*;
    let error = "Error creating service. Try to start with admin rights";
    let manager_access = ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE;
    let manager = ServiceManager::local_computer(None::<&str>, manager_access).expect(error);

    let my_service_info = ServiceInfo {
        name: OsString::from(service_name),
        display_name: OsString::from(service_name),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: PathBuf::from(bin_path),
        launch_arguments: vec![OsString::from("--service"), OsString::from("-l"), OsString::from("alfis_log.txt")],
        dependencies: vec![],
        account_name: None, // run as System
        account_password: None,
    };

    let my_service = manager.create_service(&my_service_info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START).expect(error);
    let _ = my_service.set_description(&OsStr::new(SERVICE_DESCRIPTION));
    thread::sleep(Duration::from_secs(1));
    match my_service.start(&[OsStr::new("--service")]) {
        Ok(_) => println!("Service successfully installed and started"),
        Err(e) => println!("Error starting service: {}", e)
    }
}

// Function to uninstall a Windows service
pub fn uninstall_service(service_name: &str) {
    use windows_service::service_manager::*;
    use windows_service::service::*;
    let error = "Error creating service. Try to start with admin rights";
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).expect(error);
    let service_access = ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE;
    match manager.open_service(&OsStr::new(service_name), service_access) {
        Ok(service) => {
            let _ = service.stop();
            thread::sleep(Duration::from_secs(2));
            let _ = service.delete();
        }
        Err(e) => println!("Error opening service. Try running with admin rights: {}", e)
    }
}