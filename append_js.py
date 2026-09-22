with open("static/app.js", "a", encoding="utf-8") as f:
    f.write("""
// --- Google Sign-In Callback ---
function handleCredentialResponse(response) {
    const data = JSON.parse(atob(response.credential.split(".")[1]));
    document.getElementById("g_id_onload").style.display = "none";
    document.querySelector(".g_id_signin").style.display = "none";
    const userProfile = document.getElementById("user-profile");
    userProfile.classList.remove("hidden");
    userProfile.classList.add("flex");
    document.getElementById("user-avatar").src = data.picture;
    document.getElementById("user-name").textContent = data.name;
    sessionStorage.setItem("google_token", response.credential);
}

document.addEventListener("DOMContentLoaded", () => {
    const logoutBtn = document.getElementById("btn-logout");
    if(logoutBtn) {
        logoutBtn.addEventListener("click", () => {
            sessionStorage.removeItem("google_token");
            document.getElementById("user-profile").classList.add("hidden");
            document.getElementById("user-profile").classList.remove("flex");
            document.querySelector(".g_id_signin").style.display = "block";
        });
    }
});
""")
print("Appended Google OAuth to app.js")
