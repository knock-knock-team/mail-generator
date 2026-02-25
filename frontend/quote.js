const quoteForm = document.getElementById("quote-form");
const statusEl = document.getElementById("form-status");
const captchaQuestion = document.getElementById("captcha-question");
const captchaRefresh = document.getElementById("captcha-refresh");

let captchaToken = "";
let config = {};

const MAX_TOTAL_BYTES = 50 * 1024 * 1024;

async function loadConfig() {
  try {
    const res = await fetch("/api/config");
    if (!res.ok) throw new Error("config load failed");
    config = await res.json();
    updatePageContent();
  } catch (err) {
    console.warn("Could not load config:", err);
  }
}

function updatePageContent() {
  const companyNameEls = document.querySelectorAll("[data-config='companyName']");
  companyNameEls.forEach(el => {
    el.textContent = config.companyName || el.textContent;
  });
}

const fieldMessages = {
  phone: {
    required: "Необходимо заполнить «Номер телефона».",
    format: "Значение «Номер телефона» неверно!",
  },
  email: {
    required: "Необходимо заполнить «Адрес электронной почты».",
    format: "Значение «Адрес электронной почты» неверно!",
  },
  inn: {
    required: "Необходимо заполнить «ИНН компании».",
    format: "Значение «ИНН компании» неверно!",
  },
  companyName: {
    required: "Необходимо заполнить «Название компании».",
  },
  project: {
    required: "Необходимо заполнить «Проект».",
  },
  message: {
    required: "Необходимо заполнить «Сообщение».",
  },
  files: {
    size: "Файлы не должны превышать 50 МБ.",
  },
  captcha: {
    invalid: "Неправильный проверочный код.",
  },
  consent: {
    required: "Необходимо согласие на обработку данных.",
  },
};

function setError(field, message) {
  const el = document.querySelector(`[data-error="${field}"]`);
  if (el) {
    el.textContent = message || "";
  }
}

function clearErrors() {
  document.querySelectorAll("[data-error]").forEach((el) => {
    el.textContent = "";
  });
}

async function loadCaptcha() {
  captchaQuestion.textContent = "Загрузка...";
  try {
    const res = await fetch("/api/captcha");
    if (!res.ok) {
      throw new Error("captcha");
    }
    const data = await res.json();
    captchaToken = data.token;
    captchaQuestion.textContent = data.question;
  } catch (err) {
    captchaQuestion.textContent = "Не удалось загрузить код";
  }
}

function formatFileNames(files) {
  if (!files || files.length === 0) {
    return "Файл не выбран";
  }
  return Array.from(files).map(file => file.name).join(", ");
}

function updateFileLabel(input) {
  const label = document.querySelector(`[data-file-name="${input.name}"]`);
  if (label) {
    label.textContent = formatFileNames(input.files);
  }
}

function totalFileSize() {
  let total = 0;
  document.querySelectorAll("input[type='file']").forEach((input) => {
    Array.from(input.files || []).forEach((file) => {
      total += file.size;
    });
  });
  return total;
}

function clientValidate(formData) {
  const errors = {};
  if (!formData.get("phone")?.trim()) {
    errors.phone = "required";
  }
  if (!formData.get("email")?.trim()) {
    errors.email = "required";
  }
  if (!formData.get("inn")?.trim()) {
    errors.inn = "required";
  }
  if (!formData.get("companyName")?.trim()) {
    errors.companyName = "required";
  }
  if (!formData.get("project")?.trim()) {
    errors.project = "required";
  }
  if (!formData.get("message")?.trim()) {
    errors.message = "required";
  }
  if (!formData.get("consent")) {
    errors.consent = "required";
  }
  if (totalFileSize() > MAX_TOTAL_BYTES) {
    errors.files = "size";
  }
  return errors;
}

function showErrors(errors) {
  Object.entries(errors).forEach(([field, code]) => {
    const message = fieldMessages[field]?.[code] || "Ошибка";
    setError(field, message);
  });
}

if (quoteForm) {
  quoteForm.querySelectorAll("input[type='file']").forEach((input) => {
    input.addEventListener("change", () => updateFileLabel(input));
    updateFileLabel(input);
  });

  quoteForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    clearErrors();
    statusEl.textContent = "";

    const formData = new FormData(quoteForm);
    formData.set("captchaToken", captchaToken);

    const clientErrors = clientValidate(formData);
    if (Object.keys(clientErrors).length > 0) {
      showErrors(clientErrors);
      return;
    }

    statusEl.textContent = "Отправляем...";

    try {
      const res = await fetch("/api/quote", {
        method: "POST",
        body: formData,
      });

      const data = await res.json();
      if (!res.ok || !data.ok) {
        showErrors(data.errors || { server: "email" });
        statusEl.textContent = "Не удалось отправить запрос.";
        await loadCaptcha();
        return;
      }

      statusEl.textContent = "Запрос отправлен. Спасибо!";
      quoteForm.reset();
      quoteForm.querySelectorAll("input[type='file']").forEach((input) => updateFileLabel(input));
      await loadCaptcha();
    } catch (err) {
      statusEl.textContent = "Ошибка сети. Попробуйте еще раз.";
    }
  });
}

if (captchaRefresh) {
  captchaRefresh.addEventListener("click", () => {
    loadCaptcha();
  });
}

loadConfig();

if (quoteForm) {
  loadCaptcha();
}
