// Include necessary imports
use eframe::{egui, App, Frame};
use open;
use rfd::FileDialog;
use std::process::Command;
use std::sync::{Arc, Mutex};
use ureq::Agent;

// Structure for the application
struct SecurityScannerApp {
    output: Arc<Mutex<String>>,
    is_running: Arc<Mutex<bool>>,
    xml_path: Arc<Mutex<Option<String>>>,
    download_url: String,
    download_path: Arc<Mutex<Option<String>>>,
    report_path: Arc<Mutex<String>>,
    // New fields for YARA functionality
    selected_tool: Arc<Mutex<String>>,
    yara_rules_path: Arc<Mutex<Option<String>>>,
    scan_path: Arc<Mutex<Option<String>>>,
    // Checkboxes for OpenSCAP additional arguments
    oscap_checkboxes: Arc<Mutex<OpenScapOptions>>,
    // Checkboxes for YARA additional arguments
    yara_checkboxes: Arc<Mutex<YaraOptions>>,
}

// Structures for checkboxes options
#[derive(Default, Clone)]
struct OpenScapOptions {
    skip_valid: bool,
    verbose: bool,
    oval_results: bool,
    dont_send_results: bool,
}

#[derive(Default, Clone)]
struct YaraOptions {
    recursive: bool,
    fast_scan: bool,
    no_warnings: bool,
    print_tags: bool,
}

impl Default for SecurityScannerApp {
    fn default() -> Self {
        Self {
            output: Arc::new(Mutex::new(String::new())),
            is_running: Arc::new(Mutex::new(false)),
            xml_path: Arc::new(Mutex::new(None)),
            download_url: "https://redos.red-soft.ru/support/secure/redos.xml".to_string(),
            download_path: Arc::new(Mutex::new(None)),
            report_path: Arc::new(Mutex::new("/tmp/report.html".to_string())),
            selected_tool: Arc::new(Mutex::new("OpenSCAP".to_string())),
            yara_rules_path: Arc::new(Mutex::new(None)),
            scan_path: Arc::new(Mutex::new(None)),
            oscap_checkboxes: Arc::new(Mutex::new(OpenScapOptions::default())),
            yara_checkboxes: Arc::new(Mutex::new(YaraOptions::default())),
        }
    }
}

impl App for SecurityScannerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut Frame) {
        // Apply a visual style for a better look
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.heading("🔍 Security Scanner GUI");
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.separator();

            // Tool selection
            ui.horizontal(|ui| {
                ui.label("Выберите инструмент:");
                let mut selected_tool = self.selected_tool.lock().unwrap();
                egui::ComboBox::from_label("")
                    .selected_text(selected_tool.clone())
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut *selected_tool, "OpenSCAP".to_string(), "OpenSCAP");
                        ui.selectable_value(&mut *selected_tool, "YARA".to_string(), "YARA");
                    });
            });

            ui.separator();

            let selected_tool = self.selected_tool.lock().unwrap().clone();

            if selected_tool == "OpenSCAP" {
                // OpenSCAP Functionality
                ui.heading("OpenSCAP Сканирование");

                ui.separator();

                // Section for downloading XML file
                ui.group(|ui| {
                    ui.label("1. Загрузите описание уязвимостей:");

                    ui.horizontal(|ui| {
                        if ui.button("Загрузить XML").clicked() {
                            let download_url = self.download_url.clone();
                            let download_path_clone = Arc::clone(&self.download_path);
                            let output_clone = Arc::clone(&self.output);
                            let running_clone = Arc::clone(&self.is_running);

                            *running_clone.lock().unwrap() = true;
                            *output_clone.lock().unwrap() = "Начало загрузки XML-файла...".to_string();

                            // Start downloading in a separate thread
                            std::thread::spawn(move || {
                                let agent = Agent::new();

                                let response = agent.get(&download_url).call();

                                match response {
                                    Ok(resp) => {
                                        let content = resp.into_string();
                                        match content {
                                            Ok(text) => {
                                                // Save the file via save dialog
                                                if let Some(path) = FileDialog::new()
                                                    .add_filter("XML", &["xml"])
                                                    .set_title("Сохранить XML-файл как")
                                                    .save_file()
                                                {
                                                    if let Err(e) = std::fs::write(&path, text) {
                                                        let mut out = output_clone.lock().unwrap();
                                                        *out = format!("Не удалось сохранить файл: {}", e);
                                                    } else {
                                                        let mut path_lock = download_path_clone.lock().unwrap();
                                                        *path_lock = Some(path.to_string_lossy().to_string());
                                                        let mut out = output_clone.lock().unwrap();
                                                        *out = format!(
                                                            "XML-файл успешно загружен и сохранён по пути: {}",
                                                            path.display()
                                                        );
                                                    }
                                                } else {
                                                    let mut out = output_clone.lock().unwrap();
                                                    *out = "Загрузка отменена пользователем.".to_string();
                                                }
                                            }
                                            Err(e) => {
                                                let mut out = output_clone.lock().unwrap();
                                                *out = format!("Ошибка чтения содержимого ответа: {}", e);
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        let mut out = output_clone.lock().unwrap();
                                        *out = format!("Ошибка загрузки файла: {}", e);
                                    }
                                }
                                *running_clone.lock().unwrap() = false;
                            });
                        }

                        // Display download status
                        let download_path = self.download_path.lock().unwrap();
                        if let Some(ref path) = *download_path {
                            ui.label(format!("Сохранено как: {}", path));
                        } else {
                            ui.label("Файл не загружен");
                        }
                    });
                });

                ui.separator();

                // Section for selecting XML file for scanning
                ui.group(|ui| {
                    ui.label("2. Выберите XML-файл для сканирования:");

                    ui.horizontal(|ui| {
                        if ui.button("Выбрать XML для сканирования").clicked() {
                            if let Some(path) = FileDialog::new()
                                .add_filter("SCAP Content", &["xml"])
                                .set_title("Выберите XML-файл для сканирования")
                                .pick_file()
                            {
                                let path_str = path.to_string_lossy().to_string();
                                let mut xml = self.xml_path.lock().unwrap();
                                *xml = Some(path_str.clone());
                                let mut output = self.output.lock().unwrap();
                                *output = format!("Выбранный XML-файл: {}", path.display());
                            }
                        }

                        // Display selected path
                        let xml = self.xml_path.lock().unwrap();
                        if let Some(ref path) = *xml {
                            ui.label(format!("Выбранный файл: {}", path));
                        } else {
                            ui.label("Файл не выбран");
                        }
                    });
                });

                ui.separator();

                // Section for additional options (checkboxes)
                ui.group(|ui| {
                    ui.label("3. Дополнительные опции для сканирования:");

                    let mut oscap_options = self.oscap_checkboxes.lock().unwrap();

                    ui.vertical(|ui| {
                        ui.checkbox(&mut oscap_options.skip_valid, "Пропустить проверку на валидность (--skip-valid)");
                        ui.checkbox(&mut oscap_options.verbose, "Подробный вывод (--verbose)");
                        ui.checkbox(&mut oscap_options.oval_results, "Сохранить результаты OVAL (--oval-results)");
                        ui.checkbox(&mut oscap_options.dont_send_results, "Не отправлять результаты (--dont-send-results)");
                    });
                });

                ui.separator();

                // Section for starting the scan
                ui.group(|ui| {
                    ui.label("4. Запустите сканирование:");

                    if *self.is_running.lock().unwrap() {
                        ui.add(egui::Label::new("Выполнение сканирования...").wrap(false));
                    } else {
                        if ui.button("Запустить сканирование").clicked() {
                            let output_clone = Arc::clone(&self.output);
                            let running_clone = Arc::clone(&self.is_running);
                            let xml_clone = Arc::clone(&self.xml_path);
                            let oscap_options_clone = Arc::clone(&self.oscap_checkboxes);
                            let report_path_clone = Arc::clone(&self.report_path);

                            *running_clone.lock().unwrap() = true;
                            *output_clone.lock().unwrap() = "Начало сканирования...".to_string();

                            // Start scanning in a separate thread
                            std::thread::spawn(move || {
                                let xml_path = {
                                    let xml = xml_clone.lock().unwrap();
                                    match &*xml {
                                        Some(path) => path.clone(),
                                        None => {
                                            let mut out = output_clone.lock().unwrap();
                                            *out = "Не выбран XML-файл для сканирования.".to_string();
                                            *running_clone.lock().unwrap() = false;
                                            return;
                                        }
                                    }
                                };

                                let oscap_options = {
                                    let options = oscap_options_clone.lock().unwrap();
                                    options.clone()
                                };

                                // Paths for results and report
                                let results_path = "/tmp/results.xml";
                                let report_path = {
                                    let rp = report_path_clone.lock().unwrap();
                                    rp.clone()
                                };

                                // Form command with additional options
                                let mut args = vec![
                                    "oval",
                                    "eval",
                                    "--results",
                                    results_path,
                                    "--report",
                                    &report_path,
                                ];

                                // Add selected options
                                if oscap_options.skip_valid {
                                    args.push("--skip-valid");
                                }
                                if oscap_options.verbose {
                                    args.push("--verbose");
                                }
                                if oscap_options.oval_results {
                                    args.push("--oval-results");
                                }
                                if oscap_options.dont_send_results {
                                    args.push("--dont-send-results");
                                }

                                args.push(&xml_path);

                                let output = Command::new("oscap")
                                    .args(&args)
                                    .output();

                                match output {
                                    Ok(output) => {
                                        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                                        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                                        let combined = format!("STDOUT:\n{}\nSTDERR:\n{}", stdout, stderr);
                                        let mut out = output_clone.lock().unwrap();
                                        *out = combined;
                                    }
                                    Err(e) => {
                                        let mut out = output_clone.lock().unwrap();
                                        *out = format!("Ошибка при запуске OpenSCAP: {}", e);
                                    }
                                }
                                *running_clone.lock().unwrap() = false;
                            });
                        }
                    }
                });

                ui.separator();

                // Section for displaying output
                ui.group(|ui| {
                    ui.label("5. Вывод:");

                    egui::ScrollArea::vertical()
                        .max_height(200.0)
                        .show(ui, |ui| {
                            let output = self.output.lock().unwrap();
                            ui.add(
                                egui::TextEdit::multiline(&mut output.clone())
                                    .desired_rows(10)
                                    .desired_width(f32::INFINITY)
                                    .font(egui::TextStyle::Monospace),
                            );
                        });
                });

                ui.separator();

                // Section for opening the report
                ui.group(|ui| {
                    ui.label("6. Оцените результаты:");

                    ui.horizontal(|ui| {
                        if ui.button("Открыть HTML-отчет").clicked() {
                            let report_path = self.report_path.lock().unwrap().clone();
                            if std::path::Path::new(&report_path).exists() {
                                if let Err(e) = open::that(&report_path) {
                                    let mut out = self.output.lock().unwrap();
                                    *out = format!("Не удалось открыть отчет: {}", e);
                                } else {
                                    let mut out = self.output.lock().unwrap();
                                    *out = format!("Открытие отчета: {}", report_path);
                                }
                            } else {
                                let mut out = self.output.lock().unwrap();
                                *out = format!("Отчет не найден по пути: {}", report_path);
                            }
                        }

                        if ui.button("Скачать отчет").clicked() {
                            let report_path = self.report_path.lock().unwrap().clone();
                            if std::path::Path::new(&report_path).exists() {
                                if let Some(save_path) = FileDialog::new()
                                    .add_filter("HTML", &["html", "htm"])
                                    .set_title("Сохранить отчет как")
                                    .save_file()
                                {
                                    match std::fs::copy(&report_path, &save_path) {
                                        Ok(_) => {
                                            let mut out = self.output.lock().unwrap();
                                            *out = format!("Отчет успешно скопирован в: {}", save_path.display());
                                        }
                                        Err(e) => {
                                            let mut out = self.output.lock().unwrap();
                                            *out = format!("Ошибка при копировании отчета: {}", e);
                                        }
                                    }
                                } else {
                                    let mut out = self.output.lock().unwrap();
                                    *out = "Скачивание отчета отменено пользователем.".to_string();
                                }
                            } else {
                                let mut out = self.output.lock().unwrap();
                                *out = format!("Отчет не найден по пути: {}", report_path);
                            }
                        }
                    });
                });

            } else if selected_tool == "YARA" {
                // YARA Functionality
                ui.heading("YARA Сканирование");

                ui.separator();

                // Section for selecting YARA rules file
                ui.group(|ui| {
                    ui.label("1. Выберите файл правил YARA:");

                    ui.horizontal(|ui| {
                        if ui.button("Выбрать файл правил").clicked() {
                            if let Some(path) = FileDialog::new()
                                .add_filter("YARA Rules", &["yar", "yara"])
                                .set_title("Выберите файл правил YARA")
                                .pick_file()
                            {
                                let path_str = path.to_string_lossy().to_string();
                                let mut rules_path = self.yara_rules_path.lock().unwrap();
                                *rules_path = Some(path_str.clone());
                                let mut output = self.output.lock().unwrap();
                                *output = format!("Выбран файл правил YARA: {}", path.display());
                            }
                        }

                        // Display selected rules file
                        let rules_path = self.yara_rules_path.lock().unwrap();
                        if let Some(ref path) = *rules_path {
                            ui.label(format!("Выбранный файл: {}", path));
                        } else {
                            ui.label("Файл правил не выбран");
                        }
                    });
                });

                ui.separator();

                // Section for selecting scan path
                ui.group(|ui| {
                    ui.label("2. Выберите файл или папку для сканирования:");

                    ui.horizontal(|ui| {
                        if ui.button("Выбрать файл для сканирования").clicked() {
                            if let Some(path) = FileDialog::new()
                                .set_title("Выберите файл для сканирования")
                                .pick_file()
                            {
                                let path_str = path.to_string_lossy().to_string();
                                let mut scan_path = self.scan_path.lock().unwrap();
                                *scan_path = Some(path_str.clone());
                                let mut output = self.output.lock().unwrap();
                                *output = format!("Выбран файл для сканирования: {}", path.display());
                            }
                        }

                        if ui.button("Выбрать папку для сканирования").clicked() {
                            if let Some(path) = FileDialog::new()
                                .set_title("Выберите папку для сканирования")
                                .pick_folder()
                            {
                                let path_str = path.to_string_lossy().to_string();
                                let mut scan_path = self.scan_path.lock().unwrap();
                                *scan_path = Some(path_str.clone());
                                let mut output = self.output.lock().unwrap();
                                *output = format!("Выбрана папка для сканирования: {}", path.display());
                            }
                        }

                        // Display selected scan path
                        let scan_path = self.scan_path.lock().unwrap();
                        if let Some(ref path) = *scan_path {
                            ui.label(format!("Сканируемый путь: {}", path));
                        } else {
                            ui.label("Путь для сканирования не выбран");
                        }
                    });
                });

                ui.separator();

                // Section for additional options (checkboxes)
                ui.group(|ui| {
                    ui.label("3. Дополнительные опции для сканирования:");

                    let mut yara_options = self.yara_checkboxes.lock().unwrap();

                    ui.vertical(|ui| {
                        ui.checkbox(&mut yara_options.recursive, "Рекурсивное сканирование (-r)");
                        ui.checkbox(&mut yara_options.fast_scan, "Быстрое сканирование (-f)");
                        ui.checkbox(&mut yara_options.no_warnings, "Не показывать предупреждения (-w)");
                        ui.checkbox(&mut yara_options.print_tags, "Показать теги (-t)");
                    });
                });

                ui.separator();

                // Section for starting the scan
                ui.group(|ui| {
                    ui.label("4. Запустите сканирование:");

                    if *self.is_running.lock().unwrap() {
                        ui.add(egui::Label::new("Выполнение сканирования...").wrap(false));
                    } else {
                        if ui.button("Запустить сканирование").clicked() {
                            let output_clone = Arc::clone(&self.output);
                            let running_clone = Arc::clone(&self.is_running);
                            let rules_path_clone = Arc::clone(&self.yara_rules_path);
                            let scan_path_clone = Arc::clone(&self.scan_path);
                            let yara_options_clone = Arc::clone(&self.yara_checkboxes);

                            *running_clone.lock().unwrap() = true;
                            *output_clone.lock().unwrap() = "Начало сканирования...".to_string();

                            // Start scanning in a separate thread
                            std::thread::spawn(move || {
                                let rules_path = {
                                    let rules = rules_path_clone.lock().unwrap();
                                    match &*rules {
                                        Some(path) => path.clone(),
                                        None => {
                                            let mut out = output_clone.lock().unwrap();
                                            *out = "Не выбран файл правил YARA.".to_string();
                                            *running_clone.lock().unwrap() = false;
                                            return;
                                        }
                                    }
                                };

                                let scan_path = {
                                    let scan = scan_path_clone.lock().unwrap();
                                    match &*scan {
                                        Some(path) => path.clone(),
                                        None => {
                                            let mut out = output_clone.lock().unwrap();
                                            *out = "Не выбран путь для сканирования.".to_string();
                                            *running_clone.lock().unwrap() = false;
                                            return;
                                        }
                                    }
                                };

                                let yara_options = {
                                    let options = yara_options_clone.lock().unwrap();
                                    options.clone()
                                };

                                // Form command with additional options
                                let mut args = Vec::new();

                                if yara_options.recursive {
                                    args.push("-r");
                                }
                                if yara_options.fast_scan {
                                    args.push("-f");
                                }
                                if yara_options.no_warnings {
                                    args.push("-w");
                                }
                                if yara_options.print_tags {
                                    args.push("-t");
                                }

                                args.push(&rules_path);
                                args.push(&scan_path);

                                let output = Command::new("yara")
                                    .args(&args)
                                    .output();

                                match output {
                                    Ok(output) => {
                                        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                                        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                                        let combined = format!("STDOUT:\n{}\nSTDERR:\n{}", stdout, stderr);
                                        let mut out = output_clone.lock().unwrap();
                                        *out = combined;
                                    }
                                    Err(e) => {
                                        let mut out = output_clone.lock().unwrap();
                                        *out = format!("Ошибка при запуске YARA: {}", e);
                                    }
                                }
                                *running_clone.lock().unwrap() = false;
                            });
                        }
                    }
                });

                ui.separator();

                // Section for displaying output
                ui.group(|ui| {
                    ui.label("5. Вывод:");

                    egui::ScrollArea::vertical()
                        .max_height(200.0)
                        .show(ui, |ui| {
                            let output = self.output.lock().unwrap();
                            ui.add(
                                egui::TextEdit::multiline(&mut output.clone())
                                    .desired_rows(10)
                                    .desired_width(f32::INFINITY)
                                    .font(egui::TextStyle::Monospace),
                            );
                        });
                });
            }
        });
    }
}

fn main() {
    let app = SecurityScannerApp::default();
    let native_options = eframe::NativeOptions::default();
    eframe::run_native(
        "Security Scanner GUI",
        native_options,
        Box::new(|_cc| Box::new(app)),
    );
}
