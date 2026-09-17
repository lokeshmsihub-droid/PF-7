const apiKey = "super-secret-token-abcdef1234567890";

function renderComment(untrustedInput) {
    // DOM XSS
    document.getElementById("comments").innerHTML = untrustedInput;
}
