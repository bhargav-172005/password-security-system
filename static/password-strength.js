document.addEventListener("DOMContentLoaded", () => {
    const passwordInput = document.getElementById("password");
    const bar = document.getElementById("strength-bar");
    const text = document.getElementById("strength-text");
    const rulesList = document.getElementById("password-requirements");

    if (!passwordInput || !bar || !text || !rulesList) return;

    const rules = {
        length: value => value.length >= 8 && value.length <= 128,
        upper: value => /[A-Z]/.test(value),
        lower: value => /[a-z]/.test(value),
        number: value => /\d/.test(value),
        special: value => /[^A-Za-z0-9]/.test(value)
    };

    passwordInput.addEventListener("input", () => {
        const value = passwordInput.value;
        let passed = 0;

        Object.entries(rules).forEach(([name, test]) => {
            const item = rulesList.querySelector(`[data-rule="${name}"]`);
            const success = test(value);
            if (success) passed++;
            item.classList.toggle("passed", success);
        });

        bar.className = "strength-bar";
        if (!value) {
            bar.style.width = "0%";
            text.textContent = "Password strength: Not entered";
        } else if (passed <= 2) {
            bar.style.width = "33%";
            bar.classList.add("weak");
            text.textContent = "Password strength: Weak";
        } else if (passed <= 4) {
            bar.style.width = "66%";
            bar.classList.add("medium");
            text.textContent = "Password strength: Medium";
        } else {
            bar.style.width = "100%";
            bar.classList.add("strong");
            text.textContent = "Password strength: Strong";
        }
    });
});
