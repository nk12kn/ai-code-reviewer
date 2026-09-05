@echo off
echo ======================================================================
echo   AI Code Reviewer - Push to GitHub
echo   Target: https://github.com/nk12kn/ai-code-reviewer
echo ======================================================================
echo.
echo [*] Pushing codebase to GitHub main branch...
echo [*] Note: If prompted, log into your GitHub account in the browser window.
echo.

git push -u origin main --force

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ======================================================================
    echo   [SUCCESS] Code pushed successfully to:
    echo   https://github.com/nk12kn/ai-code-reviewer
    echo.
    echo   Now deploy online for free in 1 click at:
    echo   https://render.com/deploy?repo=https://github.com/nk12kn/ai-code-reviewer
    echo ======================================================================
) else (
    echo.
    echo [ERROR] Push failed. Please verify your GitHub access or token.
)

pause
