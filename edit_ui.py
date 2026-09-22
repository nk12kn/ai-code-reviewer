import os
import re

html_path = "static/index.html"
with open(html_path, "r", encoding="utf-8") as f:
    content = f.read()

# Remove AdSense
content = re.sub(r'<!-- Google AdSense -->\s*<script[^>]*></script>', '', content)

# Add Google OAuth client library
oauth_script = '<script src="https://accounts.google.com/gsi/client" async defer></script>\n'
content = content.replace('<!-- Tailwind CSS CDN -->', oauth_script + '    <!-- Tailwind CSS CDN -->')

# Add Sign-in button to header and project info to About
nav_replacement = """
                <!-- Google Sign-In -->
                <div id="g_id_onload"
                     data-client_id="YOUR_GOOGLE_CLIENT_ID_HERE"
                     data-context="signin"
                     data-ux_mode="popup"
                     data-callback="handleCredentialResponse"
                     data-auto_prompt="false">
                </div>
                <div class="g_id_signin"
                     data-type="standard"
                     data-shape="rectangular"
                     data-theme="outline"
                     data-text="signin_with"
                     data-size="small"
                     data-logo_alignment="left">
                </div>
                <div id="user-profile" class="hidden items-center gap-2 text-xs font-medium text-gray-300">
                    <img id="user-avatar" class="w-6 h-6 rounded-full" src="" alt="User avatar">
                    <span id="user-name"></span>
                    <button id="btn-logout" class="text-rose-400 hover:text-rose-300 ml-2"><i class="fa-solid fa-right-from-bracket"></i></button>
                </div>
"""

content = content.replace('<!-- Quick Action / Engine Status -->', nav_replacement + '<!-- Quick Action / Engine Status -->')

# Add "About Project" section to the bottom
about_section = """
    <!-- About Project Section -->
    <section id="about-project" class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12 border-t border-gray-800/80">
        <div class="bg-[#111827] border border-gray-800 rounded-xl p-6 md:p-8">
            <h3 class="text-2xl font-bold text-white mb-6 border-b border-gray-800 pb-2">About Project</h3>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6 text-sm text-gray-300">
                <div>
                    <p class="mb-2"><strong class="text-cyan-400">Project Name:</strong> AI Code Reviewer & Security Auditor</p>
                    <p class="mb-2"><strong class="text-cyan-400">Developed By:</strong> [Your Name Here]</p>
                    <p class="mb-2"><strong class="text-cyan-400">College/University:</strong> [Your College Name Here]</p>
                    <p class="mb-2"><strong class="text-cyan-400">Department:</strong> [Your Department Here]</p>
                    <p class="mb-2"><strong class="text-cyan-400">Project Guide:</strong> [Your Project Guide Name Here]</p>
                </div>
                <div class="flex items-center md:justify-end">
                    <a href="https://github.com/yourusername/yourrepo" target="_blank" class="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-white rounded-lg flex items-center gap-2 transition border border-gray-700">
                        <i class="fa-brands fa-github text-lg"></i> View Source Code on GitHub
                    </a>
                </div>
            </div>
        </div>
    </section>
"""

content = content.replace('<!-- Section 3: Common Vulnerabilities Detected -->', about_section + '    <!-- Section 3: Common Vulnerabilities Detected -->')

with open(html_path, "w", encoding="utf-8") as f:
    f.write(content)

print("Updated index.html")
