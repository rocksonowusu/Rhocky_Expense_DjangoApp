const usernameField = document.querySelector("#usernameField");
const feedbackField = document.querySelector(".invalid-feeback");
const emailField = document.querySelector("#emailField");
const passwordField = document.querySelector("#passwordField");
const invalidEmail = document.querySelector(".invalid-email");
const username_success = document.querySelector(".username_success");
const email_succes = document.querySelector(".email_success");
const showPassword = document.querySelector(".showPassword");
const password_pointer = document.querySelector("#password_pointer");
const submit_btn = document.querySelector(".submit-btn");



password_pointer.addEventListener("mouseover", () => {
  password_pointer.style.cursor = "pointer";
});

password_pointer.addEventListener("mouseout", () => {
  password_pointer.style.cursor = "default";
});

const handleToggle = () => {
  if (passwordField.type === "password") {
    passwordField.type = "text";
    showPassword.textContent = "HIDE";
  } else {
    passwordField.type = "password";
    showPassword.textContent = "SHOW";
  }
};
showPassword.addEventListener("click", handleToggle);

usernameField.addEventListener("keyup", (e) => {
  console.log("77777", 77777);

  const usernameVal = e.target.value;
  username_success.textContent = `Checking ${usernameVal}`;

  username_success.style.display = "block";

  usernameField.classList.remove("is-invalid");
  feedbackField.style.display = "none";

  if (usernameVal.length > 0) {
    fetch("/authentication/user-validation/", {
      body: JSON.stringify({ username: usernameVal }),
      method: "POST",
    })
      .then((res) => res.json())
      .then((data) => {
        console.log("data", data);
        username_success.style.display = "none";
        if (data.username_error) {
          submit_btn.disabled = true;
          usernameField.classList.add("is-invalid");
          feedbackField.style.display = "block";
          feedbackField.innerHTML = `<p style="color:red;">${data.username_error}</p>`;
        } else {
          submit_btn.removeAttribute("disabled");
        }
      }); // making an API call to the route
  }
});

emailField.addEventListener("keyup", (e) => {
  const emailVal = e.target.value;

  email_succes.textContent = `Checking ${emailVal}`;

  emailField.classList.remove("is-invalid");
  invalidEmail.style.display = "none";
  email_succes.style.display = "block";

  if (emailVal.length > 0) {
    fetch("/authentication/email-validation/", {
      body: JSON.stringify({ email: emailVal }),
      method: "POST",
    })
      .then((res) => res.json())
      .then((data) => {
        console.log("data", data);
        email_succes.style.display = "none";
        if (data.email_error) {
          submit_btn.disabled = true;
          emailField.classList.add("is-invalid");
          invalidEmail.style.display = "block";
          invalidEmail.innerHTML = `<p style="color:red;">${data.email_error}</p>`;
        } else {
          submit_btn.removeAttribute("disabled");
        }
      }); // making an API call to the route
  }
});
