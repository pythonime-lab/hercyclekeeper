"use strict";

// ─── Plural rule helpers ──────────────────────────────────────────────────────

function pluralSlavic(n) {
  const abs = Math.abs(n);
  const mod10 = abs % 10;
  const mod100 = abs % 100;
  if (mod10 === 1 && mod100 !== 11) return "one";
  if (mod10 >= 2 && mod10 <= 4 && (mod100 < 10 || mod100 >= 20)) return "few";
  return "many";
}

function pluralSimple(n) {
  return Math.abs(n) === 1 ? "one" : "many";
}

const PLURAL_FN = {
  en: pluralSimple,
  ru: pluralSlavic,
  be: pluralSlavic,
  es: pluralSimple,
};

// ─── Locale data ──────────────────────────────────────────────────────────────

const LOCALES = {
  // ── English ────────────────────────────────────────────────────────────────
  en: {
    // About section (About, Privacy, Support, Disclaimer, Accessibility)
    about_tab_developer: "Developer",
    about_tab_privacy: "Privacy",
    about_tab_disclaimer: "Disclaimer",
    privacy_title: "Privacy Guarantee",
    privacy_info:
      "Your Cycle Keeper collects zero data. This app: Stores all data locally on your device only; Has no servers, no accounts, no cloud storage; Has no analytics, no tracking, no telemetry; Has no ads, no third-party code; Never transmits any data anywhere; Is encrypted with your PIN via AES-256-GCM. Your health data is yours alone.",

    about_title: "About Your Cycle Keeper",
    about_info:
      "Your Cycle Keeper is free software built with care for privacy. Based on the Calendar Rhythm Method and Standard Days Method for cycle estimation. For informational purposes only. Version: 1.0.0-beta. License: GPL v3 License. Developer: pythonime-lab. Found a bug or have a suggestion? Visit our GitHub repository.",

    support_title: "Support Development",
    support_info:
      "Your Cycle Keeper is free forever with no ads, no tracking, and no data collection. If you find it helpful and would like to support continued development, you can buy me a coffee! Your support helps keep this project maintained and ad-free for everyone. Thank you! 💜",

    disclaimer_title: "Medical Disclaimer",
    disclaimer_info:
      "⚠️ This app provides cycle estimations based on average biological patterns. It is not medical advice and must not be used as a substitute for professional medical consultation. Your Cycle Keeper predicts your cycle by tracking patterns and estimating ovulation timing. Actual cycle timing can vary due to stress, illness, medications, and many other factors. Do not use this app as a contraceptive or fertility guarantee. Always consult a qualified healthcare professional for medical decisions.",

    accessibility_title: "Accessibility",
    accessibility_info:
      "Your Cycle Keeper follows WCAG 2.0 accessibility standards: Tab/Shift+Tab: Navigate forward/backward through all interactive elements; Arrow Keys: Navigate calendar dates (complex grid component); Enter/Space: Activate buttons and links; Escape: Close modals and return focus to trigger element; PIN Entry: Type digits 0-9 and Backspace on all PIN screens; Form Controls: Native keyboard support for inputs, selects, and textareas; Screen Readers: Semantic HTML with proper ARIA labels and roles; Focus Management: Visible focus indicators, logical tab order. Standards based on Salesforce Accessibility Guidelines.",
    
    cycle_stats: "Cycle Stats",
    avg_length: "Avg Length",
    cycles_logged: "Cycles Logged",
    avg_period: "Avg Period",
    fertile_days: "Fertile Days",
    symptom_tracking: "Symptom Tracking",
    period: "Period",
    ovulation: "Ovulation",
    flow: "Flow",
    pain: "Pain",
    mood: "Mood",
    how_it_works: "How it Works",
    how_it_works_p1:
      "Your Cycle Keeper estimates your fertile window by tracking cycle patterns. Ovulation is estimated ~14 days before your next period. Fertile days are calculated as day 8 through (cycle length − 11).",
    how_it_works_p2:
      "For regular 28-day cycles, this means days 8–17 are typically fertile, with ovulation around day 14.",
    disclaimer: "Disclaimer",
    estimation_disclaimer:
      "⚠️ This is an estimation tool only. Not for contraception. Stress, illness & medications can shift timing.",
    no_symptoms_logged: "No symptoms logged yet — start by logging today",
    cycle_history: "Cycle History",
    all_months: "All Months",
    cycle_day: "Cycle Day",
    until_next: "Until Next",
    day_1: "Day 1",
    avg_length_short: "Avg Length",
    period_short: "Period",
    fertile: "Fertile",
    ovulation_short: "Ovulation",
    luteal: "Luteal",

    // Storage / init errors
    storage_error_title: "Storage Error",
    storage_error_msg: "Could not access storage. Please refresh the page.",
    db_error_title: "Database Error",
    db_error_msg:
      "Could not initialize app storage. Please try refreshing the page.",

    // Lock screen / PIN
    unlock_subtitle: "Enter your PIN to unlock your private health data",
    too_many_attempts: "Too many attempts. Try again in {secs}s.",
    locked_out: "🚫 Too many attempts. Locked for 60 seconds.",
    lockout_ended: "Lockout ended. Try again.",
    incorrect_pin_one: "Incorrect PIN. {remaining} attempt remaining.",
    incorrect_pin_many: "Incorrect PIN. {remaining} attempts remaining.",
    decryption_failed: "Decryption failed. Data may be corrupted.",
    error_try_again: "An error occurred. Please try again.",

    // Forgot PIN / reset
    forgot_pin_title: "Forgot PIN?",
    forgot_pin_msg:
      "This will permanently erase all your cycle data and reset Your Cycle Keeper. This cannot be undone. Are you sure?",
    forgot_pin_confirm: "Yes, erase and reset",
    reset_complete_title: "Reset Complete",
    reset_complete_msg:
      "Your Cycle Keeper has been reset. Please set a new PIN to get started.",
    reset_failed_title: "Reset Failed",
    reset_failed_msg:
      "Could not clear your data. Please refresh the page and try again.",

    // Save / setup
    save_failed_title: "Save Failed",
    save_failed_msg: "Could not save your data. Please try again.",
    missing_date_title: "Missing Date",
    missing_date_msg: "Please enter the first day of your last period.",
    set_pin_title: "Set a PIN",
    set_pin_msg: "Enter a 4-digit PIN to protect your data.",
    setup_error_title: "Setup Error",
    setup_error_msg:
      "Could not complete setup. Please refresh the page and try again.",

    // Note
    note_count: "{count} / 500",


    // Symptom modals
    set_flow: "Set Flow",
    save: "Save",
    cancel: "Cancel",
    ok: "OK",
    refresh: "Refresh",
    pain_label: "Pain {value} / 10",
    set_pain: "Set Pain",
    mood_low: "Low Mood",
    mood_happy: "Happy",
    mood_neutral: "Neutral",
    set_mood: "Set Mood",

    // Reminder banner
    period_expected_in_one: "Period expected in {n} day",
    period_expected_in_many: "Period expected in {n} days",

    // Phase messages
    phase_menstruation: "Your period 🩸",
    phase_follicular: "Building up ✨",
    phase_fertile: "Fertile days 🌿",
    phase_ovulation: "Ovulation day 🌟",
    phase_luteal: "Luteal phase 🌙",

    // Phase subtitles
    subtitle_menstruation: "Day {day} of your period",
    subtitle_fertile: "Days {start}–{end} are fertile",
    subtitle_ovulation: "Peak fertility today",
    subtitle_other: "Next period in {n} days",

    // Status card
    now: "Now",
    bar_day: "Day {n}",

    // History / insights
    cycle_history_empty:
      "Log at least 2 period start dates to see cycle history.",
    history_days_one: "{n} day",
    history_days_many: "{n} days",
    no_data_yet: "No tracking data logged yet",

    // Chart labels
    chart_full_year: "Full Year {year}",
    chart_month_year: "{month} {year}",

    // Chart download errors
    download_failed_title: "Download Failed",
    download_failed_msg: "Could not download chart. Please try again.",

    // Settings validation
    invalid_date_title: "Invalid Date",
    invalid_date_msg: "Please enter a valid last period date.",
    invalid_cycle_title: "Invalid Cycle Length",
    invalid_cycle_msg: "Cycle length must be between 20 and 45 days.",
    invalid_duration_title: "Invalid Duration",
    invalid_duration_msg: "Period duration must be between 1 and 10 days.",
    update_predictions_title: "Update Predictions?",
    update_predictions_msg:
      "This will recalculate all cycle predictions based on your new settings. Your logged symptoms and notes will remain unchanged. Continue?",
    update_predictions_confirm: "Yes, Update",

    // Backup status
    backup_never: "Last backup: Never",
    backup_today: "Last backup: Today",
    backup_yesterday: "Last backup: Yesterday",
    backup_days_ago_one: "Last backup: {n} day ago",
    backup_days_ago_many: "Last backup: {n} days ago",
    backup_overdue_one: "Last backup: {n} day ago — overdue!",
    backup_overdue_many: "Last backup: {n} days ago — overdue!",

    // Export/import
    export_backup_title: "Export Backup",
    export_backup_msg:
      "Your backup will be exported as an encrypted file. It can only be decrypted with your PIN. Keep it private.",
    export: "Export",
    export_failed_title: "Export Failed",
    export_failed_msg: "Could not export backup. Please try again.",
    enter_backup_pin_title: "Enter Backup PIN",
    enter_backup_pin_msg:
      "Enter the PIN that was active when this backup was created.",
    incorrect_pin_simple: "Incorrect PIN. Try again.",
    restored_title: "Restored",
    restored_msg: "Your backup has been restored successfully.",
    invalid_backup_title: "Invalid Backup",
    invalid_backup_msg: "This backup format is not supported.",
    import_failed_title: "Import Failed",
    import_failed_msg: "Could not read backup file. Ensure it's valid.",

    // Storage info
    storage_used: "{sizeKB} KB (IndexedDB)",
    storage_unknown: "Unknown",

    // Erase data
    erase_title: "Erase All Data",
    erase_msg:
      "This will permanently delete all your cycle data and cannot be undone. Are you absolutely sure?",
    erase_confirm: "Yes, erase everything",
    erase_failed_title: "Erase Failed",
    erase_failed_msg: "Could not erase data. Please try again.",

    // Change PIN
    confirm_new_pin: "Confirm New PIN",
    enter_new_pin: "Enter New PIN",
    reenter_pin_msg: "Re-enter your new PIN to confirm.",
    choose_pin_msg: "Choose a 4-digit PIN.",
    pins_no_match: "PINs don't match. Try again.",
    pin_changed_title: "PIN Changed",
    pin_changed_msg:
      "Your PIN has been updated and all data re-encrypted.\n\nNote: any backups made before this change will still require your old PIN to restore.",
    pin_change_failed_title: "PIN Change Failed",
    pin_change_failed_msg: "Could not update PIN. Please try again.",

    // Calendar aria-labels
    calendar_day_period: "period day",
    calendar_day_ovulation: "ovulation day",
    calendar_day_fertile: "fertile day",
    calendar_day_regular: "regular day",

    // Phase badge labels (short, uppercase-safe)
    follicular: "Follicular",

    // Language switcher
    language_label: "Language",
    lang_en: "English",
    lang_ru: "Русский",
    lang_es: "Español",

    // Settings HTML labels
    settings_cycle_tab: "Cycle Settings",
    settings_security_tab: "Security & Privacy",
    settings_cycle_section: "Cycle Settings",
    settings_last_period: "Last period start date",
    settings_cycle_length: "Average cycle length (days)",
    settings_period_duration: "Period duration (days)",
    settings_update_btn: "Update Predictions",
    settings_security_section: "Security & Privacy",
    settings_change_pin: "Change PIN",
    settings_export: "Export Encrypted Backup",
    settings_import: "Import Encrypted Backup",
    settings_storage_label: "Storage used:",
    settings_storage_calculating: "Calculating...",
    settings_erase: "Erase All Data",

    // Onboarding
    onboard_sub: "Track Your Period and Cycle Privately",
    onboard_tagline:
      "Track your flow, mood, and symptoms — all on your device. Free, ad-free, fully accessible, and privacy-first.",
    beta_label: "Beta",
    beta_warning_text:
      "This app is currently in active development. Features may change and bugs may occur.",
    ob_last_period: "First day of your last period",
    ob_cycle_len: "Average cycle length (days)",
    ob_period_dur: "Average period duration (days)",
    pin_setup_title: "🔒 Set a 4-digit PIN",
    pin_setup_sub_1: "Your PIN encrypts all data locally.",
    pin_setup_sub_2: "Your Cycle Keeper never sends data anywhere.",
    pin_setup_sub_3: "If you forget your PIN, data will be erased.",
    onboard_start_btn: "Start Tracking ✨",
    privacy_note_aes: "AES-256-GCM encrypted.",
    privacy_note_rest:
      "Data never leaves your device. No accounts, no tracking, forever free.",
    timeout_before: "⏱️ Session expires in",
    timeout_after: "s of inactivity — tap to reset",

    // Flow labels
    flow_light: "Light",
    flow_medium: "Medium",
    flow_heavy: "Heavy",

    // Toast messages
    settings_saved_toast: "Settings saved",
    status_no_data_hint: "Set your last period date in Settings to get cycle predictions.",

    // Storage full error
    storage_full_title: "Storage Full",
    storage_full_msg: "Your device storage is full. Please export your data or clear some logs to free up space.",

    // Forgot PIN second confirmation
    forgot_pin_confirm2_title: "Last Warning",
    forgot_pin_confirm2_msg: "ALL your period tracking data will be permanently deleted and cannot be recovered. This cannot be undone.",
    forgot_pin_confirm2_btn: "Yes, Delete Everything",

    // Cycle history
    no_cycle_history: "No cycle history yet. Log at least 2 periods to see history.",
    history_showing: "Showing last {shown} of {total} cycles",

    // History legend
    legend_short: "Short (<26d)",
    legend_normal: "Normal (26–32d)",
    legend_long: "Long (>32d)",
  },

  // ── Russian ────────────────────────────────────────────────────────────────
  ru: {
    storage_error_title: "Ошибка хранилища",
    storage_error_msg:
      "Не удалось получить доступ к хранилищу. Пожалуйста, обновите страницу.",
    db_error_title: "Ошибка базы данных",
    db_error_msg:
      "Не удалось инициализировать хранилище. Пожалуйста, обновите страницу.",
      
    cycle_stats: "Статистика цикла",
    avg_length: "Средняя длина",
    cycles_logged: "Отмечено циклов",
    avg_period: "Средняя менстр.",
    fertile_days: "Фертильные дни",
    symptom_tracking: "Отслеживание симптомов",
    period: "Менструация",
    ovulation: "Овуляция",
    flow: "Выделения",
    pain: "Боль",
    mood: "Настроение",
    how_it_works: "Как это работает",
    how_it_works_p1:
      "Your Cycle Keeper оценивает ваше фертильное окно, отслеживая паттерны цикла. Овуляция оценивается ~ за 14 дней до следующей менструации. Фертильные дни рассчитываются по формуле: день 8 — (длина цикла − 11).",
    how_it_works_p2:
      "При регулярном цикле в 28 дней это означает, что дни с 8 по 17 обычно являются фертильными с овуляцией примерно на 14 день.",
    disclaimer: "Отказ от ответственности",
    estimation_disclaimer:
      "⚠️ Это только инструмент для оценки. Не для контрацепции. Стресс, болезни и лекарства могут изменить сроки.",
    no_symptoms_logged: "Симптомы пока не отмечены — начните отмечать их сегодня",
    cycle_history: "История цикла",
    all_months: "Все месяцы",
    cycle_day: "День цикла",
    until_next: "До следующей",
    day_1: "День 1",
    avg_length_short: "Ср. длина",
    period_short: "Менструация",
    fertile: "Фертильные",
    ovulation_short: "Овуляция",
    luteal: "Лютеиновая",

    unlock_subtitle: "Введите PIN для разблокировки личных данных о здоровье",
    too_many_attempts: "Слишком много попыток. Повторите через {secs}с.",
    locked_out: "🚫 Слишком много попыток. Заблокировано на 60 секунд.",
    lockout_ended: "Блокировка снята. Повторите попытку.",
    incorrect_pin_one: "Неверный PIN. Осталась {remaining} попытка.",
    incorrect_pin_few: "Неверный PIN. Осталось {remaining} попытки.",
    incorrect_pin_many: "Неверный PIN. Осталось {remaining} попыток.",
    decryption_failed: "Ошибка расшифровки. Данные могут быть повреждены.",
    error_try_again: "Произошла ошибка. Пожалуйста, попробуйте снова.",

    forgot_pin_title: "Забыли PIN?",
    forgot_pin_msg:
      "Это действие безвозвратно удалит все данные о цикле и сбросит Your Cycle Keeper. Это нельзя отменить. Вы уверены?",
    forgot_pin_confirm: "Да, удалить и сбросить",
    reset_complete_title: "Сброс выполнен",
    reset_complete_msg:
      "Your Cycle Keeper был сброшен. Пожалуйста, установите новый PIN для начала работы.",
    reset_failed_title: "Ошибка сброса",
    reset_failed_msg:
      "Не удалось удалить данные. Пожалуйста, обновите страницу и попробуйте снова.",

    save_failed_title: "Ошибка сохранения",
    save_failed_msg:
      "Не удалось сохранить данные. Пожалуйста, попробуйте снова.",
    missing_date_title: "Дата не указана",
    missing_date_msg: "Пожалуйста, введите первый день последней менструации.",
    set_pin_title: "Установите PIN",
    set_pin_msg: "Введите 4-значный PIN для защиты данных.",
    setup_error_title: "Ошибка настройки",
    setup_error_msg:
      "Не удалось завершить настройку. Пожалуйста, обновите страницу и попробуйте снова.",

    note_count: "{count} / 500",

    set_flow: "Интенсивность",
    save: "Сохранить",
    cancel: "Отмена",
    ok: "ОК",
    refresh: "Обновить",
    pain_label: "Боль {value} / 10",
    set_pain: "Боль",
    mood_low: "Плохое настроение",
    mood_happy: "Хорошее настроение",
    mood_neutral: "Нейтральное",
    set_mood: "Настроение",

    period_expected_in_one: "Менструация ожидается через {n} день",
    period_expected_in_few: "Менструация ожидается через {n} дня",
    period_expected_in_many: "Менструация ожидается через {n} дней",

    phase_menstruation: "Ваша менструация 🩸",
    phase_follicular: "Фолликулярная фаза ✨",
    phase_fertile: "Фертильные дни 🌿",
    phase_ovulation: "День овуляции 🌟",
    phase_luteal: "Лютеиновая фаза 🌙",

    subtitle_menstruation: "День {day} вашей менструации",
    subtitle_fertile: "Дни {start}–{end} — фертильные",
    subtitle_ovulation: "Пик фертильности сегодня",
    subtitle_other: "До следующей менструации {n} дней",

    now: "Сейчас",
    bar_day: "День {n}",

    cycle_history_empty:
      "Отметьте не менее 2 начал менструации, чтобы увидеть историю цикла.",
    history_days_one: "{n} день",
    history_days_few: "{n} дня",
    history_days_many: "{n} дней",
    no_data_yet: "Данные ещё не добавлены",

    chart_full_year: "Весь {year} год",
    chart_month_year: "{month} {year}",

    download_failed_title: "Ошибка загрузки",
    download_failed_msg:
      "Не удалось скачать график. Пожалуйста, попробуйте снова.",

    invalid_date_title: "Неверная дата",
    invalid_date_msg:
      "Пожалуйста, введите корректную дату последней менструации.",
    invalid_cycle_title: "Неверная длина цикла",
    invalid_cycle_msg: "Длина цикла должна быть от 20 до 45 дней.",
    invalid_duration_title: "Неверная продолжительность",
    invalid_duration_msg:
      "Продолжительность менструации должна быть от 1 до 10 дней.",
    update_predictions_title: "Обновить прогнозы?",
    update_predictions_msg:
      "Это пересчитает все прогнозы цикла на основе новых настроек. Записи симптомов и заметки останутся без изменений. Продолжить?",
    update_predictions_confirm: "Да, обновить",

    backup_never: "Резервная копия: никогда",
    backup_today: "Резервная копия: сегодня",
    backup_yesterday: "Резервная копия: вчера",
    backup_days_ago_one: "Резервная копия: {n} день назад",
    backup_days_ago_few: "Резервная копия: {n} дня назад",
    backup_days_ago_many: "Резервная копия: {n} дней назад",
    backup_overdue_one: "Резервная копия: {n} день назад — устарела!",
    backup_overdue_few: "Резервная копия: {n} дня назад — устарела!",
    backup_overdue_many: "Резервная копия: {n} дней назад — устарела!",

    export_backup_title: "Экспорт резервной копии",
    export_backup_msg:
      "Резервная копия будет экспортирована в зашифрованном файле. Расшифровать её можно только с помощью вашего PIN. Храните в безопасном месте.",
    export: "Экспортировать",
    export_failed_title: "Ошибка экспорта",
    export_failed_msg:
      "Не удалось экспортировать резервную копию. Пожалуйста, попробуйте снова.",
    enter_backup_pin_title: "Введите PIN резервной копии",
    enter_backup_pin_msg:
      "Введите PIN, который использовался при создании этой резервной копии.",
    incorrect_pin_simple: "Неверный PIN. Попробуйте снова.",
    restored_title: "Восстановлено",
    restored_msg: "Резервная копия успешно восстановлена.",
    invalid_backup_title: "Неверный формат резервной копии",
    invalid_backup_msg: "Этот формат резервной копии не поддерживается.",
    import_failed_title: "Ошибка импорта",
    import_failed_msg:
      "Не удалось прочитать файл резервной копии. Убедитесь в его корректности.",

    storage_used: "{sizeKB} КБ (IndexedDB)",
    storage_unknown: "Неизвестно",

    erase_title: "Удалить все данные",
    erase_msg:
      "Это безвозвратно удалит все данные о цикле. Вы абсолютно уверены?",
    erase_confirm: "Да, удалить всё",
    erase_failed_title: "Ошибка удаления",
    erase_failed_msg:
      "Не удалось удалить данные. Пожалуйста, попробуйте снова.",

    confirm_new_pin: "Подтвердите новый PIN",
    enter_new_pin: "Введите новый PIN",
    reenter_pin_msg: "Введите новый PIN ещё раз для подтверждения.",
    choose_pin_msg: "Выберите 4-значный PIN.",
    pins_no_match: "PIN-коды не совпадают. Попробуйте снова.",
    pin_changed_title: "PIN изменён",
    pin_changed_msg:
      "Ваш PIN обновлён, все данные перешифрованы.\n\nПримечание: для восстановления резервных копий, созданных до этого изменения, потребуется старый PIN.",
    pin_change_failed_title: "Ошибка смены PIN",
    pin_change_failed_msg:
      "Не удалось обновить PIN. Пожалуйста, попробуйте снова.",

    calendar_day_period: "день менструации",
    calendar_day_ovulation: "день овуляции",
    calendar_day_fertile: "фертильный день",
    calendar_day_regular: "обычный день",

    follicular: "Фолликулярная",

    about_tab_developer: "Разработчик",
    about_tab_privacy: "Приватность",
    about_tab_disclaimer: "Отказ от ответственности",
    language_label: "Язык",
    lang_en: "English",
    lang_ru: "Русский",
    lang_es: "Español",

    settings_cycle_tab: "Настройки цикла",
    settings_security_tab: "Безопасность",
    settings_cycle_section: "Настройки цикла",
    settings_last_period: "Дата начала последней менструации",
    settings_cycle_length: "Средняя длина цикла (дни)",
    settings_period_duration: "Продолжительность менструации (дни)",
    settings_update_btn: "Обновить прогнозы",
    settings_security_section: "Безопасность и конфиденциальность",
    settings_change_pin: "Изменить PIN",
    settings_export: "Экспортировать резервную копию",
    settings_import: "Импортировать резервную копию",
    settings_storage_label: "Использовано памяти:",
    settings_storage_calculating: "Вычисляется...",
    settings_erase: "Удалить все данные",

    // Onboarding
    onboard_sub: "Отслеживайте цикл приватно",
    onboard_tagline:
      "Следите за выделениями, настроем и симптомами — всё на вашем устройстве. Бесплатно, без рекламы, с заботой о конфиденциальности.",
    beta_label: "Бета",
    beta_warning_text:
      "Приложение находится в активной разработке. Возможны изменения функций и ошибки.",
    ob_last_period: "Первый день последней менструации",
    ob_cycle_len: "Средняя длина цикла (дни)",
    ob_period_dur: "Средняя длительность менструации (дни)",
    pin_setup_title: "🔒 Задайте 4-значный PIN",
    pin_setup_sub_1: "Ваш PIN шифрует все данные локально.",
    pin_setup_sub_2: "Your Cycle Keeper никогда не отправляет данные.",
    pin_setup_sub_3: "Если вы забудете PIN, данные будут удалены.",
    onboard_start_btn: "Начать отслеживание ✨",
    privacy_note_aes: "Шифрование AES-256-GCM.",
    privacy_note_rest:
      "Данные не покидают ваше устройство. Без аккаунтов, без слежки, навсегда бесплатно.",
    timeout_before: "⏱️ Сессия истекает через",
    timeout_after: "с бездействия — нажмите для сброса",

    // Flow labels
    flow_light: "Слабые",
    flow_medium: "Умеренные",
    flow_heavy: "Обильные",

    // Toast messages
    settings_saved_toast: "Настройки сохранены",
    status_no_data_hint: "Укажите дату последней менструации в настройках для получения прогнозов.",

    // Storage full error
    storage_full_title: "Хранилище заполнено",
    storage_full_msg: "Хранилище устройства заполнено. Экспортируйте данные или удалите некоторые записи.",

    // Forgot PIN second confirmation
    forgot_pin_confirm2_title: "Последнее предупреждение",
    forgot_pin_confirm2_msg: "ВСЕ ваши данные отслеживания цикла будут безвозвратно удалены. Это действие нельзя отменить.",
    forgot_pin_confirm2_btn: "Да, удалить всё",

    // Cycle history
    no_cycle_history: "История циклов пока отсутствует. Зафиксируйте хотя бы 2 менструации.",
    history_showing: "Показано последних {shown} из {total} циклов",

    // History legend
    legend_short: "Короткий (<26д)",
    legend_normal: "Нормальный (26–32д)",
    legend_long: "Длинный (>32д)",
  },

  // ── Belarusian (inactive — translations preserved for future use) ───────────
  be: {
    storage_error_title: "Памылка сховішча",
    storage_error_msg:
      "Не ўдалося атрымаць доступ да сховішча. Калі ласка, абнавіце старонку.",
    db_error_title: "Памылка базы даных",
    db_error_msg:
      "Не ўдалося ініцыялізаваць сховішча. Калі ласка, абнавіце старонку.",

    unlock_subtitle:
      "Увядзіце PIN для разблакавання асабістых даных аб здароўі",
    too_many_attempts: "Занадта шмат спроб. Паўтарыце праз {secs}с.",
    locked_out: "🚫 Занадта шмат спроб. Заблакавана на 60 секунд.",
    lockout_ended: "Блакаванне зняты. Паўтарыце спробу.",
    incorrect_pin_one: "Няслушны PIN. Засталася {remaining} спроба.",
    incorrect_pin_few: "Няслушны PIN. Засталося {remaining} спробы.",
    incorrect_pin_many: "Няслушны PIN. Засталося {remaining} спроб.",
    decryption_failed: "Памылка дэшыфравання. Даныя могуць быць пашкоджаны.",
    error_try_again: "Адбылася памылка. Калі ласка, паўтарыце спробу.",

    forgot_pin_title: "Забылі PIN?",
    forgot_pin_msg:
      "Гэта назаўжды выдаліць усе даныя пра цыкл і скіне Your Cycle Keeper. Гэта нельга адмяніць. Вы ўпэўнены?",
    forgot_pin_confirm: "Так, выдаліць і скінуць",
    reset_complete_title: "Скід выкананы",
    reset_complete_msg:
      "Your Cycle Keeper быў скінуты. Калі ласка, усталюйце новы PIN для пачатку працы.",
    reset_failed_title: "Памылка скіду",
    reset_failed_msg:
      "Не ўдалося выдаліць даныя. Калі ласка, абнавіце старонку і паўтарыце спробу.",

    save_failed_title: "Памылка захавання",
    save_failed_msg: "Не ўдалося захаваць даныя. Калі ласка, паўтарыце спробу.",
    missing_date_title: "Дата не ўказана",
    missing_date_msg: "Калі ласка, увядзіце першы дзень апошняй менструацыі.",
    set_pin_title: "Усталюйце PIN",
    set_pin_msg: "Увядзіце 4-значны PIN для абароны даных.",
    setup_error_title: "Памылка наладкі",
    setup_error_msg:
      "Не ўдалося завяршыць наладку. Калі ласка, абнавіце старонку і паўтарыце спробу.",

    note_count: "{count} / 500",

    set_flow: "Інтэнсіўнасць",
    save: "Захаваць",
    cancel: "Адмена",
    ok: "ОК",
    refresh: "Абнавіць",
    pain_label: "Боль {value} / 10",
    set_pain: "Боль",
    mood_low: "Дрэнны настрой",
    mood_happy: "Добры настрой",
    mood_neutral: "Нейтральны",
    set_mood: "Настрой",

    period_expected_in_one: "Ваша менструацыя чакаецца праз {n} дзень",
    period_expected_in_few: "Ваша менструацыя чакаецца праз {n} дні",
    period_expected_in_many: "Ваша менструацыя чакаецца праз {n} дзён",

    phase_menstruation: "Ваша менструацыя 🩸",
    phase_follicular: "Фалікулярная фаза ✨",
    phase_fertile: "Фертыльныя дні 🌿",
    phase_ovulation: "Дзень авуляцыі 🌟",
    phase_luteal: "Лютэінавая фаза 🌙",

    subtitle_menstruation: "Дзень {day} вашай менструацыі",
    subtitle_fertile: "Дні {start}–{end} — фертыльныя",
    subtitle_ovulation: "Пік фертыльнасці сёння",
    subtitle_other: "Да наступнай менструацыі {n} дзён",

    now: "Зараз",
    bar_day: "Дзень {n}",

    cycle_history_empty:
      "Адзначце не менш за 2 пачаткі менструацыі, каб убачыць гісторыю цыкла.",
    history_days_one: "{n} дзень",
    history_days_few: "{n} дні",
    history_days_many: "{n} дзён",
    no_data_yet: "Даныя яшчэ не дададзены",

    chart_full_year: "Увесь {year} год",
    chart_month_year: "{month} {year}",

    download_failed_title: "Памылка загрузкі",
    download_failed_msg:
      "Не ўдалося спампаваць графік. Калі ласка, паўтарыце спробу.",

    invalid_date_title: "Няслушная дата",
    invalid_date_msg:
      "Калі ласка, увядзіце карэктную дату апошняй менструацыі.",
    invalid_cycle_title: "Няслушная даўжыня цыкла",
    invalid_cycle_msg: "Даўжыня цыкла мусіць быць ад 20 да 45 дзён.",
    invalid_duration_title: "Няслушная працягласць",
    invalid_duration_msg:
      "Працягласць менструацыі мусіць быць ад 1 да 10 дзён.",
    update_predictions_title: "Абнавіць прагнозы?",
    update_predictions_msg:
      "Гэта пераразлічыць усе прагнозы цыкла на аснове новых налад. Запісы сімптомаў і нататкі застануцца без змен. Працягнуць?",
    update_predictions_confirm: "Так, абнавіць",

    backup_never: "Рэзервовая копія: ніколі",
    backup_today: "Рэзервовая копія: сёння",
    backup_yesterday: "Рэзервовая копія: учора",
    backup_days_ago_one: "Рэзервовая копія: {n} дзень таму",
    backup_days_ago_few: "Рэзервовая копія: {n} дні таму",
    backup_days_ago_many: "Рэзервовая копія: {n} дзён таму",
    backup_overdue_one: "Рэзервовая копія: {n} дзень таму — пратэрмінавана!",
    backup_overdue_few: "Рэзервовая копія: {n} дні таму — пратэрмінавана!",
    backup_overdue_many: "Рэзервовая копія: {n} дзён таму — пратэрмінавана!",

    export_backup_title: "Экспарт рэзервовай копіі",
    export_backup_msg:
      "Рэзервовая копія будзе экспартавана ў зашыфраваным файле. Расшыфраваць яе можна толькі з дапамогай вашага PIN. Захоўвайце ў бяспечным месцы.",
    export: "Экспартаваць",
    export_failed_title: "Памылка экспарту",
    export_failed_msg:
      "Не ўдалося экспартаваць рэзервовую копію. Калі ласка, паўтарыце спробу.",
    enter_backup_pin_title: "Увядзіце PIN рэзервовай копіі",
    enter_backup_pin_msg:
      "Увядзіце PIN, які выкарыстоўваўся пры стварэнні гэтай рэзервовай копіі.",
    incorrect_pin_simple: "Няслушны PIN. Паўтарыце спробу.",
    restored_title: "Адноўлена",
    restored_msg: "Рэзервовая копія паспяхова адноўлена.",
    invalid_backup_title: "Няслушны фармат рэзервовай копіі",
    invalid_backup_msg: "Гэты фармат рэзервовай копіі не падтрымліваецца.",
    import_failed_title: "Памылка імпарту",
    import_failed_msg:
      "Не ўдалося прачытаць файл рэзервовай копіі. Пераканайцеся ў яго карэктнасці.",

    storage_used: "{sizeKB} КБ (IndexedDB)",
    storage_unknown: "Невядома",

    erase_title: "Выдаліць усе даныя",
    erase_msg:
      "Гэта назаўжды выдаліць усе даныя пра цыкл. Вы абсалютна ўпэўнены?",
    erase_confirm: "Так, выдаліць усё",
    erase_failed_title: "Памылка выдалення",
    erase_failed_msg:
      "Не ўдалося выдаліць даныя. Калі ласка, паўтарыце спробу.",

    confirm_new_pin: "Пацвердзіце новы PIN",
    enter_new_pin: "Увядзіце новы PIN",
    reenter_pin_msg: "Увядзіце новы PIN яшчэ раз для пацверджання.",
    choose_pin_msg: "Выберыце 4-значны PIN.",
    pins_no_match: "PIN-коды не супадаюць. Паўтарыце спробу.",
    pin_changed_title: "PIN зменены",
    pin_changed_msg:
      "Ваш PIN абноўлены, усе даныя перашыфраваны.\n\nЗаўвага: для аднаўлення рэзервовых копій, створаных да гэтай змены, спатрэбіцца стары PIN.",
    pin_change_failed_title: "Памылка змены PIN",
    pin_change_failed_msg:
      "Не ўдалося абнавіць PIN. Калі ласка, паўтарыце спробу.",

    calendar_day_period: "дзень менструацыі",
    calendar_day_ovulation: "дзень авуляцыі",
    calendar_day_fertile: "фертыльны дзень",
    calendar_day_regular: "звычайны дзень",

    follicular: "Фалікулярная",

    about_tab_developer: "Распрацоўшчык",
    about_tab_privacy: "Прыватнасць",
    about_tab_disclaimer: "Адмова ад адказнасці",
    language_label: "Мова",
    lang_en: "English",
    lang_ru: "Русский",
    lang_be: "Беларуская",
    lang_es: "Español",

    settings_cycle_tab: "Налады цыкла",
    settings_security_tab: "Бяспека",
    settings_cycle_section: "Налады цыкла",
    settings_last_period: "Дата пачатку апошняй менструацыі",
    settings_cycle_length: "Сярэдняя даўжыня цыкла (дні)",
    settings_period_duration: "Працягласць менструацыі (дні)",
    settings_update_btn: "Абнавіць прагнозы",
    settings_security_section: "Бяспека і прыватнасць",
    settings_change_pin: "Змяніць PIN",
    settings_export: "Экспартаваць рэзервовую копію",
    settings_import: "Імпартаваць рэзервовую копію",
    settings_storage_label: "Выкарыстана памяці:",
    settings_storage_calculating: "Вылічваецца...",
    settings_erase: "Выдаліць усе даныя",

    // Onboarding
    onboard_sub: "Адсочвайце цыкл прыватна",
    onboard_tagline:
      "Сачыце за выдзяленнямі, настроем і сімптомамі — усё на вашай прыладзе. Бясплатна, без рэкламы, з клопатам аб прыватнасці.",
    beta_label: "Бэта",
    beta_warning_text:
      "Праграма знаходзіцца ў актыўнай распрацоўцы. Магчымы змены функцый і памылкі.",
    ob_last_period: "Першы дзень апошняй менструацыі",
    ob_cycle_len: "Сярэдняя даўжыня цыкла (дні)",
    ob_period_dur: "Сярэдняя працягласць менструацыі (дні)",
    pin_setup_title: "🔒 Задаць 4-значны PIN",
    pin_setup_sub_1: "Ваш PIN шыфруе ўсе даныя лакальна.",
    pin_setup_sub_2: "Your Cycle Keeper ніколі не адпраўляе даныя.",
    pin_setup_sub_3: "Калі вы забудзецеся PIN, даныя будуць выдалены.",
    onboard_start_btn: "Пачаць адсочванне ✨",
    privacy_note_aes: "Шыфраванне AES-256-GCM.",
    privacy_note_rest:
      "Даныя не пакідаюць вашу прыладу. Без акаўнтаў, без сачэння, назаўжды бясплатна.",
    timeout_before: "⏱️ Сесія заканчваецца праз",
    timeout_after: "с бяздзейнасці — націсніце для скіду",

    // Flow labels
    flow_light: "Слабыя",
    flow_medium: "Умераныя",
    flow_heavy: "Абутныя",

    // Toast messages
    settings_saved_toast: "Налады захаваны",
    status_no_data_hint: "Усталюйце дату апошняй менструацыі ў налатах для атрымання прагнозаў.",

    // Storage full error
    storage_full_title: "Сховішча запоўнена",
    storage_full_msg: "Сховішча прылады запоўнена. Экспартуйце дадзеныя або выдаліце некаторыя запісы.",

    // Forgot PIN second confirmation
    forgot_pin_confirm2_title: "Апошняе папярэджанне",
    forgot_pin_confirm2_msg: "УСЕ вашы дадзеныя будуць назаўжды выдалены. Гэта дзеянне немагчыма адмяніць.",
    forgot_pin_confirm2_btn: "Так, выдаліць усё",

    // Cycle history
    no_cycle_history: "Гісторыя цыклаў пакуль адсутнічае. Зафіксуйце хаця б 2 менструацыі.",
    history_showing: "Паказана апошніх {shown} з {total} цыклаў",

    // History legend
    legend_short: "Кароткі (<26д)",
    legend_normal: "Нармальны (26–32д)",
    legend_long: "Доўгі (>32д)",
  },

  // ── Spanish ────────────────────────────────────────────────────────────────
  es: {
    storage_error_title: "Error de almacenamiento",
    storage_error_msg:
      "No se pudo acceder al almacenamiento. Por favor, recarga la página.",
    db_error_title: "Error de base de datos",
    cycle_stats: "Estadísticas del ciclo",
    avg_length: "Longitud promedio",
    cycles_logged: "Ciclos registrados",
    avg_period: "Período promedio",
    fertile_days: "Días fértiles",
    symptom_tracking: "Seguimiento de síntomas",
    period: "Período",
    ovulation: "Ovulación",
    flow: "Flujo",
    pain: "Dolor",
    mood: "Estado de ánimo",
    how_it_works: "Cómo funciona",
    how_it_works_p1:
      "Your Cycle Keeper estima tu ventana fértil rastreando patrones del ciclo. La ovulación se estima ~14 días antes de tu próximo período. Los días fértiles se calculan como el día 8 hasta (longitud del ciclo − 11).",
    how_it_works_p2:
      "Para ciclos regulares de 28 días, esto significa que los días 8–17 suelen ser fértiles, con ovulación alrededor del día 14.",
    disclaimer: "Aviso",
    estimation_disclaimer:
      "⚠️ Esta es solo una herramienta de estimación. No es para anticoncepción. El estrés, las enfermedades y los medicamentos pueden cambiar los tiempos.",
    no_symptoms_logged: "Aún no hay síntomas registrados — comienza registrando hoy",
    cycle_history: "Historial del ciclo",
    all_months: "Todos los meses",
    cycle_day: "Día del ciclo",
    until_next: "Hasta el próximo",
    day_1: "Día 1",
    avg_length_short: "Longitud promedio",
    period_short: "Período",
    fertile: "Fértil",
    ovulation_short: "Ovulación",
    luteal: "Lútea",
    db_error_msg:
      "No se pudo inicializar el almacenamiento. Por favor, recarga la página.",

    about_tab_developer: "Desarrollador",
    about_tab_privacy: "Privacidad",
    about_tab_disclaimer: "Aviso",
    unlock_subtitle:
      "Ingresa tu PIN para desbloquear tus datos privados de salud",
    too_many_attempts: "Demasiados intentos. Inténtalo en {secs}s.",
    locked_out: "🚫 Demasiados intentos. Bloqueado por 60 segundos.",
    lockout_ended: "Bloqueo finalizado. Inténtalo de nuevo.",
    incorrect_pin_one: "PIN incorrecto. Queda {remaining} intento.",
    incorrect_pin_many: "PIN incorrecto. Quedan {remaining} intentos.",
    decryption_failed: "Error de descifrado. Los datos pueden estar dañados.",
    error_try_again: "Ocurrió un error. Por favor, inténtalo de nuevo.",

    forgot_pin_title: "¿Olvidaste el PIN?",
    forgot_pin_msg:
      "Esto eliminará permanentemente todos tus datos del ciclo y restablecerá Your Cycle Keeper. No se puede deshacer. ¿Estás segura?",
    forgot_pin_confirm: "Sí, borrar y restablecer",
    reset_complete_title: "Restablecimiento completado",
    reset_complete_msg:
      "Your Cycle Keeper ha sido restablecido. Por favor, establece un nuevo PIN para comenzar.",
    reset_failed_title: "Error al restablecer",
    reset_failed_msg:
      "No se pudieron borrar los datos. Por favor, recarga la página e inténtalo de nuevo.",

    save_failed_title: "Error al guardar",
    save_failed_msg:
      "No se pudieron guardar los datos. Por favor, inténtalo de nuevo.",
    missing_date_title: "Fecha requerida",
    missing_date_msg: "Por favor, ingresa el primer día de tu último período.",
    set_pin_title: "Establece un PIN",
    set_pin_msg: "Ingresa un PIN de 4 dígitos para proteger tus datos.",
    setup_error_title: "Error de configuración",
    setup_error_msg:
      "No se pudo completar la configuración. Por favor, recarga la página e inténtalo de nuevo.",

    note_count: "{count} / 500",

    set_flow: "Flujo",
    save: "Guardar",
    cancel: "Cancelar",
    ok: "Aceptar",
    refresh: "Recargar",
    pain_label: "Dolor {value} / 10",
    set_pain: "Dolor",
    mood_low: "Ánimo bajo",
    mood_happy: "Feliz",
    mood_neutral: "Neutral",
    set_mood: "Estado de ánimo",

    period_expected_in_one: "Periodo esperado en {n} día",
    period_expected_in_many: "Periodo esperado en {n} días",

    phase_menstruation: "Tu período 🩸",
    phase_follicular: "Fase folicular ✨",
    phase_fertile: "Días fértiles 🌿",
    phase_ovulation: "Día de ovulación 🌟",
    phase_luteal: "Fase lútea 🌙",

    subtitle_menstruation: "Día {day} de tu período",
    subtitle_fertile: "Los días {start}–{end} son fértiles",
    subtitle_ovulation: "Pico de fertilidad hoy",
    subtitle_other: "Próximo período en {n} días",

    now: "Ahora",
    bar_day: "Día {n}",

    cycle_history_empty:
      "Registra al menos 2 fechas de inicio de período para ver el historial del ciclo.",
    history_days_one: "{n} día",
    history_days_many: "{n} días",
    no_data_yet: "Aún no hay datos registrados",

    chart_full_year: "Año completo {year}",
    chart_month_year: "{month} {year}",

    download_failed_title: "Error al descargar",
    download_failed_msg:
      "No se pudo descargar el gráfico. Por favor, inténtalo de nuevo.",

    invalid_date_title: "Fecha inválida",
    invalid_date_msg:
      "Por favor, ingresa una fecha válida para el último período.",
    invalid_cycle_title: "Longitud de ciclo inválida",
    invalid_cycle_msg: "La longitud del ciclo debe estar entre 20 y 45 días.",
    invalid_duration_title: "Duración inválida",
    invalid_duration_msg:
      "La duración del período debe estar entre 1 y 10 días.",
    update_predictions_title: "¿Actualizar predicciones?",
    update_predictions_msg:
      "Esto recalculará todas las predicciones del ciclo con tu nueva configuración. Los síntomas y notas registrados no cambiarán. ¿Continuar?",
    update_predictions_confirm: "Sí, actualizar",

    backup_never: "Última copia: nunca",
    backup_today: "Última copia: hoy",
    backup_yesterday: "Última copia: ayer",
    backup_days_ago_one: "Última copia: hace {n} día",
    backup_days_ago_many: "Última copia: hace {n} días",
    backup_overdue_one: "Última copia: hace {n} día — ¡vencida!",
    backup_overdue_many: "Última copia: hace {n} días — ¡vencida!",

    export_backup_title: "Exportar copia de seguridad",
    export_backup_msg:
      "Tu copia de seguridad se exportará como un archivo cifrado. Solo puede descifrarse con tu PIN. Mantenla privada.",
    export: "Exportar",
    export_failed_title: "Error al exportar",
    export_failed_msg:
      "No se pudo exportar la copia de seguridad. Por favor, inténtalo de nuevo.",
    enter_backup_pin_title: "Ingresar PIN de copia de seguridad",
    enter_backup_pin_msg:
      "Ingresa el PIN que estaba activo cuando se creó esta copia de seguridad.",
    incorrect_pin_simple: "PIN incorrecto. Inténtalo de nuevo.",
    restored_title: "Restaurado",
    restored_msg: "Tu copia de seguridad se ha restaurado correctamente.",
    invalid_backup_title: "Copia de seguridad inválida",
    invalid_backup_msg: "Este formato de copia de seguridad no es compatible.",
    import_failed_title: "Error al importar",
    import_failed_msg:
      "No se pudo leer el archivo de copia de seguridad. Asegúrate de que sea válido.",

    storage_used: "{sizeKB} KB (IndexedDB)",
    storage_unknown: "Desconocido",

    erase_title: "Borrar todos los datos",
    erase_msg:
      "Esto eliminará permanentemente todos tus datos del ciclo y no se puede deshacer. ¿Estás absolutamente segura?",
    erase_confirm: "Sí, borrar todo",
    erase_failed_title: "Error al borrar",
    erase_failed_msg:
      "No se pudieron borrar los datos. Por favor, inténtalo de nuevo.",

    confirm_new_pin: "Confirmar nuevo PIN",
    enter_new_pin: "Ingresar nuevo PIN",
    reenter_pin_msg: "Vuelve a ingresar tu nuevo PIN para confirmar.",
    choose_pin_msg: "Elige un PIN de 4 dígitos.",
    pins_no_match: "Los PIN no coinciden. Inténtalo de nuevo.",
    pin_changed_title: "PIN cambiado",
    pin_changed_msg:
      "Tu PIN ha sido actualizado y todos los datos han sido cifrados nuevamente.\n\nNota: las copias de seguridad anteriores a este cambio aún requerirán tu PIN anterior para restaurarse.",
    pin_change_failed_title: "Error al cambiar el PIN",
    pin_change_failed_msg:
      "No se pudo actualizar el PIN. Por favor, inténtalo de nuevo.",

    calendar_day_period: "día de período",
    calendar_day_ovulation: "día de ovulación",
    calendar_day_fertile: "día fértil",
    calendar_day_regular: "día regular",

    follicular: "Folicular",

    language_label: "Idioma",
    lang_en: "English",
    lang_ru: "Русский",
    lang_es: "Español",

    settings_cycle_tab: "Configuración del ciclo",
    settings_security_tab: "Seguridad",
    settings_cycle_section: "Configuración del ciclo",
    settings_last_period: "Fecha de inicio del último período",
    settings_cycle_length: "Longitud promedio del ciclo (días)",
    settings_period_duration: "Duración del período (días)",
    settings_update_btn: "Actualizar predicciones",
    settings_security_section: "Seguridad y privacidad",
    settings_change_pin: "Cambiar PIN",
    settings_export: "Exportar copia de seguridad cifrada",
    settings_import: "Importar copia de seguridad cifrada",
    settings_storage_label: "Almacenamiento usado:",
    settings_storage_calculating: "Calculando...",
    settings_erase: "Borrar todos los datos",

    // Onboarding
    onboard_sub: "Rastrea tu período y ciclo de forma privada",
    onboard_tagline:
      "Registra tu flujo, estado de ánimo y síntomas — todo en tu dispositivo. Gratis, sin anuncios, totalmente accesible y con privacidad primero.",
    beta_label: "Beta",
    beta_warning_text:
      "Esta aplicación está en desarrollo activo. Las funciones pueden cambiar y pueden ocurrir errores.",
    ob_last_period: "Primer día de tu último período",
    ob_cycle_len: "Longitud promedio del ciclo (días)",
    ob_period_dur: "Duración promedio del período (días)",
    pin_setup_title: "🔒 Establece un PIN de 4 dígitos",
    pin_setup_sub_1: "Tu PIN cifra todos los datos localmente.",
    pin_setup_sub_2: "Your Cycle Keeper nunca envía datos a ningún lugar.",
    pin_setup_sub_3: "Si olvidas tu PIN, los datos serán borrados.",
    onboard_start_btn: "Comenzar seguimiento ✨",
    privacy_note_aes: "Cifrado AES-256-GCM.",
    privacy_note_rest:
      "Los datos nunca salen de tu dispositivo. Sin cuentas, sin rastreo, gratis para siempre.",
    timeout_before: "⏱️ La sesión expira en",
    timeout_after: "s de inactividad — toca para restablecer",

    // Flow labels
    flow_light: "Ligero",
    flow_medium: "Moderado",
    flow_heavy: "Abundante",

    // Toast messages
    settings_saved_toast: "Ajustes guardados",
    status_no_data_hint: "Configura la fecha de tu último período en Ajustes para obtener predicciones.",

    // Storage full error
    storage_full_title: "Almacenamiento lleno",
    storage_full_msg: "El almacenamiento de tu dispositivo está lleno. Por favor exporta tus datos o elimina algunos registros.",

    // Forgot PIN second confirmation
    forgot_pin_confirm2_title: "Última advertencia",
    forgot_pin_confirm2_msg: "TODOS tus datos de seguimiento serán eliminados permanentemente y no podrán recuperarse. Esto no se puede deshacer.",
    forgot_pin_confirm2_btn: "Sí, eliminar todo",

    // Cycle history
    no_cycle_history: "Aún no hay historial de ciclos. Registra al menos 2 períodos para ver el historial.",
    history_showing: "Mostrando los últimos {shown} de {total} ciclos",

    // History legend
    legend_short: "Corto (<26d)",
    legend_normal: "Normal (26–32d)",
    legend_long: "Largo (>32d)",
  },
};

// ─── State ────────────────────────────────────────────────────────────────────

const LANG_STORAGE_KEY = "yck_lang";
const SUPPORTED = ["en"];

function detectLanguage() {
  try {
    const stored = localStorage.getItem(LANG_STORAGE_KEY);
    if (stored && SUPPORTED.includes(stored)) return stored;
  } catch (_) {}
  const nav = (navigator.language || "en").split("-")[0].toLowerCase();
  return SUPPORTED.includes(nav) ? nav : "en";
}

let currentLang = detectLanguage();
let currentLocale = LOCALES[currentLang];

// Set <html lang> immediately on module load
document.documentElement.lang = currentLang;

// ─── Public API ───────────────────────────────────────────────────────────────

/** Change the active language and persist the choice. */
export function setLanguage(lang) {
  if (!SUPPORTED.includes(lang)) return;
  currentLang = lang;
  currentLocale = LOCALES[lang];
  try {
    localStorage.setItem(LANG_STORAGE_KEY, lang);
  } catch (_) {}
  document.documentElement.lang = lang;
}

/** Return the active language code. */
export function getLanguage() {
  return currentLang;
}

/** Return the list of supported language codes. */
export function getSupportedLanguages() {
  return [...SUPPORTED];
}

/**
 * Translate a key, interpolating {var} placeholders with `vars`.
 * Falls back to English, then to the raw key.
 */
export function t(key, vars) {
  let str = currentLocale[key] ?? LOCALES.en[key] ?? key;
  if (vars) {
    for (const [k, v] of Object.entries(vars)) {
      str = str.replaceAll(`{${k}}`, String(v));
    }
  }
  return str;
}

/**
 * Plural-aware translate. Selects key_one / key_few / key_many based on `count`.
 * Falls back gracefully if a plural form is missing.
 */
export function tp(key, count, vars) {
  const form = (PLURAL_FN[currentLang] ?? pluralSimple)(count);
  const candidates = [`${key}_${form}`, `${key}_many`, `${key}_other`, key];
  let str = key; // final fallback
  for (const candidate of candidates) {
    const val = currentLocale[candidate] ?? LOCALES.en[candidate];
    if (val !== undefined) {
      str = val;
      break;
    }
  }
  const allVars = { n: count, ...vars };
  for (const [k, v] of Object.entries(allVars)) {
    str = str.replaceAll(`{${k}}`, String(v));
  }
  return str;
}

/**
 * Walk the DOM and replace text / attributes on elements carrying
 * data-i18n, data-i18n-placeholder, or data-i18n-aria attributes.
 */
export function applyI18n() {
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    el.textContent = t(el.dataset.i18n);
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
    el.placeholder = t(el.dataset.i18nPlaceholder);
  });
  document.querySelectorAll("[data-i18n-aria]").forEach((el) => {
    el.setAttribute("aria-label", t(el.dataset.i18nAria));
  });
}
