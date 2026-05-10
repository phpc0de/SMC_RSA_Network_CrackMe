@echo off
echo 正在清理 VS2022 项目中的编译数据...
echo.

:: 1. 删除 VS 本地配置与数据库
if exist .vs (
    rmdir /s /q .vs
    echo [删除] .vs
)

:: 2. 删除所有项目的 Debug / Release / x64 / Win32 输出目录
for /d /r . %%d in (Debug Release x64 Win32) do (
    if exist "%%d" (
        rmdir /s /q "%%d"
        echo [删除] %%d
    )
)

:: 3. 删除所有 obj 中间目录（.obj, .pdb, .tlog 等）
for /d /r . %%d in (obj) do (
    if exist "%%d" (
        rmdir /s /q "%%d"
        echo [删除] %%d
    )
)

:: 4. 删除 nuget 包缓存（还原时自动下载）
if exist packages (
    rmdir /s /q packages
    echo [删除] packages
)

:: 5. 删除用户本地配置文件
del /s /q *.user *.suo 2>nul
echo [删除] *.user *.suo

:: ========== 以下为【编译数据专项清理】==========

:: 6. 删除 .obj / .o / .lib / .exp / .ilk / .pdb（编译/链接产物）
del /s /q *.obj *.o *.lib *.exp *.ilk *.pdb 2>nul

:: 7. 删除 .exe / .dll / .so（最终可执行文件）
del /s /q *.exe *.dll *.so 2>nul

:: 8. 删除 .bsc / .sbr（浏览信息文件，老式符号库）
del /s /q *.bsc *.sbr 2>nul

:: 9. 删除 .idb / .ipdb（增量编译 PDB 临时文件）
del /s /q *.idb *.ipdb 2>nul

:: 10. 删除 .tlog / .lastbuildstate（编译日志 / 增量状态）
del /s /q *.tlog *.lastbuildstate 2>nul

:: 11. 删除 VS 智能感知临时文件（.db / .ipch 不在项目内，但不影响项目）
if exist "%LocalAppData%\Microsoft\VisualStudio\17.0\VC\ipch" (
    echo [提示] 系统级智能感知缓存未删除（路径较长，可手动处理）
)

:: 12. 删除 CMake 生成文件（如果你还用 CMake）
del /s /q CMakeCache.txt 2>nul
for /d /r . %%d in (CMakeFiles) do (
    if exist "%%d" rmdir /s /q "%%d"
)

:: 13. 删除 vcpkg / conan 本地安装目录（如果写在项目内）
if exist vcpkg_installed (
    rmdir /s /q vcpkg_installed
    echo [删除] vcpkg_installed
)
if exist conan\
    rmdir /s /q conan
    echo [删除] conan
)

echo.
echo 清理完成！现在项目体积已最小化。
pause