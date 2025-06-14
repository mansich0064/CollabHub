document.getElementById('signupForm').addEventListener('submit', function (e) {
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    const email = document.getElementById('email').value;
    const agree = document.getElementById('agree').checked;

    // Check if passwords match
    if (password !== confirmPassword) {
        showMessage("Passwords do not match!", "error");
        e.preventDefault();  // Prevent form submission
        return;
    }

    // Check if email format is valid
    const emailPattern = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$/;
    if (!emailPattern.test(email)) {
        showMessage("Invalid email format!", "error");
        e.preventDefault();  // Prevent form submission
        return;
    }

    // Check if terms and conditions checkbox is checked
    if (!agree) {
        showMessage("You must agree to the Terms and Conditions!", "error");
        e.preventDefault();  // Prevent form submission
        return;
    }

    // If everything is valid, show success message (after form submission)
    showMessage("Form submitted successfully!", "success");
});

// Function to display message
function showMessage(message, type) {
    const messageBox = document.createElement('div');
    messageBox.classList.add('message', type);  // Add message class for styling
    messageBox.innerHTML = message;
    document.body.appendChild(messageBox);

    // Automatically hide the message after 1 minute (60000 milliseconds)
    setTimeout(function () {
        messageBox.remove();
    }, 60000);  // 60,000 milliseconds = 1 minute
}