//  Password show / hide
function togglePass(id, icon) {
    const input = document.getElementById(id);

    if (input.type === "password") {
        input.type = "text";
        icon.textContent = "👁️";
    } else {
        input.type = "password";
        icon.textContent = "🙈";
    }
}

// Signup validation
document.getElementById("signupForm").addEventListener("submit", function (e) {
    const password = document.querySelector('input[name="password"]');
    const confirmPassword = document.querySelector('input[name="confirm_password"]');
    const errorText = document.getElementById("passwordError");

    errorText.textContent = "";
    confirmPassword.classList.remove("input-error");

    if (password.value !== confirmPassword.value) {
        e.preventDefault();
        errorText.textContent = "Passwords do not match";
        confirmPassword.classList.add("input-error");
        return;
    }

    
});
