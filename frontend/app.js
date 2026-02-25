const form = document.getElementById("support-form");
const statusEl = document.getElementById("form-status");
const captchaQuestion = document.getElementById("captcha-question");
const captchaRefresh = document.getElementById("captcha-refresh");

let captchaToken = "";
let config = {};
let requestTypeSelect = null;
let serialLabel = null;
let innLabel = null;
let serialInput = null;
let innInput = null;

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
  const supportEmailEls = document.querySelectorAll("[data-config='supportEmail']");
  const supportPhoneEls = document.querySelectorAll("[data-config='supportPhone']");

  companyNameEls.forEach(el => {
    el.textContent = config.companyName || el.textContent;
  });
  supportEmailEls.forEach(el => {
    el.textContent = config.supportEmail || el.textContent;
  });
  supportPhoneEls.forEach(el => {
    el.textContent = config.supportPhone || el.textContent;
  });
}

function updateRequestTypeLabels() {
  if (!requestTypeSelect || !serialLabel || !innLabel || !serialInput || !innInput) {
    return;
  }

  const isService = requestTypeSelect.value === "Сервис";
  if (isService) {
    serialLabel.textContent = "Название компании";
    innLabel.textContent = "Страна/регион";
    serialInput.placeholder = ""
    innInput.placeholder = ""
    innInput.inputMode = "text";
  } else {
    serialLabel.textContent = "Заводской номер прибора";
    innLabel.textContent = "ИНН компании";
    serialInput.placeholder = "";
    innInput.placeholder = "";
    innInput.inputMode = "numeric";
  }
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
  message: {
    required: "Необходимо заполнить «Сообщение».",
  },
  inn: {
    format: "Значение «ИНН компании» неверно!",
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

function collectForm() {
  const formData = new FormData(form);
  return {
    requestType: formData.get("requestType"),
    lastName: formData.get("lastName"),
    firstName: formData.get("firstName"),
    middleName: formData.get("middleName"),
    phone: formData.get("phone"),
    email: formData.get("email"),
    serialNumber: formData.get("serialNumber"),
    inn: formData.get("inn"),
    message: formData.get("message"),
    consent: formData.get("consent") === "on",
    captchaToken,
    captchaAnswer: formData.get("captchaAnswer"),
  };
}

function clientValidate(payload) {
  const errors = {};
  if (!payload.phone || payload.phone.trim() === "") {
    errors.phone = "required";
  }
  if (!payload.email || payload.email.trim() === "") {
    errors.email = "required";
  }
  if (!payload.message || payload.message.trim() === "") {
    errors.message = "required";
  }
  if (!payload.consent) {
    errors.consent = "required";
  }
  return errors;
}

function showErrors(errors) {
  Object.entries(errors).forEach(([field, code]) => {
    const message = fieldMessages[field]?.[code] || "Ошибка";
    setError(field, message);
  });
}

if (form) {
  requestTypeSelect = form.querySelector("select[name='requestType']");
  serialLabel = form.querySelector("[data-field-label='serialNumber']");
  innLabel = form.querySelector("[data-field-label='inn']");
  serialInput = form.querySelector("input[name='serialNumber']");
  innInput = form.querySelector("input[name='inn']");

  if (requestTypeSelect) {
    requestTypeSelect.addEventListener("change", updateRequestTypeLabels);
    updateRequestTypeLabels();
  }

  form.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearErrors();
  statusEl.textContent = "";

  const payload = collectForm();
  const clientErrors = clientValidate(payload);
  if (Object.keys(clientErrors).length > 0) {
    showErrors(clientErrors);
    return;
  }

  statusEl.textContent = "Отправляем...";

  try {
    const res = await fetch("/api/submit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    const data = await res.json();
    if (!res.ok || !data.ok) {
      showErrors(data.errors || { server: "email" });
      statusEl.textContent = "Не удалось отправить заявку.";
      await loadCaptcha();
      return;
    }

    statusEl.textContent = "Заявка отправлена. Спасибо!";
    form.reset();
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

if (form) {
  loadCaptcha();
}
